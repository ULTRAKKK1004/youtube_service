from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
import yt_dlp
import os
import tempfile
import httpx
import aiosqlite
import datetime
import re
import json
import asyncio
import bcrypt
import urllib.parse
import shutil
from typing import Optional
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# --- 1. 모델 정의 (최상단) ---
class VideoRequest(BaseModel): url: str
class UserRegister(BaseModel): email: str; password: str; name: str
class UserLogin(BaseModel): email: str; password: str
class BlockIPRequest(BaseModel): ip: str; reason: str = ""
class UserLevelRequest(BaseModel): email: str; level: str

# 환경 변수
openwebui = os.getenv('openwebui')
llm_url = os.getenv('llm_url')
model_name = os.getenv('model_name')
SECRET_KEY = os.getenv("SECRET_KEY", "your-very-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

app = FastAPI()
DB_PATH = "youtube_cache.db"

# --- 2. 유틸리티 ---
def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    try: return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except: return False

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- 3. 인증 의존성 ---
async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): return None
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE email = ?", (payload.get("sub"),)) as cursor: return await cursor.fetchone()
    except: return None

async def get_current_admin(request: Request):
    user = await get_current_user(request)
    if not user or user["level"] != 'admin': raise HTTPException(status_code=403, detail="권한 없음")
    return user

async def get_privileged_user(request: Request):
    user = await get_current_user(request)
    if not user or user["level"] not in ['admin', 'user2']: raise HTTPException(status_code=403, detail="권한 없음")
    return user

# --- 4. 설정 및 DB ---
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup_event():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS video_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, video_id TEXT UNIQUE, title TEXT, userId TEXT, request_ip TEXT, transcript TEXT, summary TEXT, created_at TIMESTAMP, view_count INTEGER DEFAULT 1)")
        await db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, hashed_password TEXT, name TEXT, profile_pic TEXT, google_id TEXT, level TEXT DEFAULT 'user', created_at TIMESTAMP)")
        cursor = await db.execute("PRAGMA table_info(users)")
        if 'level' not in [r[1] for r in await cursor.fetchall()]: await db.execute("ALTER TABLE users ADD COLUMN level TEXT DEFAULT 'user'")
        await db.execute("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, endpoint TEXT, method TEXT, created_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS ip_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, reason TEXT, created_at TIMESTAMP)")
        admin_id = os.getenv("ADMIN_ID", "hi_man")
        async with db.execute("SELECT id FROM users WHERE email = ?", (admin_id,)) as cursor:
            if not await cursor.fetchone():
                admin_pw = os.getenv("ADMIN_PASSWORD", "itispassword")
                await db.execute("INSERT INTO users (email, hashed_password, name, level, created_at) VALUES (?, ?, ?, 'admin', ?)", (admin_id, get_password_hash(admin_pw), "최고관리자", datetime.datetime.now()))
        await db.commit()

@app.middleware("http")
async def block_ip_and_log(request: Request, call_next):
    if request.method == "OPTIONS": return await call_next(request)
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT id FROM ip_blocks WHERE ip = ?", (request.client.host,)) as cursor:
                if await cursor.fetchone(): return JSONResponse(status_code=403, content={"detail": "차단됨"})
            await db.execute("INSERT INTO access_logs (ip, endpoint, method, created_at) VALUES (?, ?, ?, ?)", (request.client.host, request.url.path, request.method, datetime.datetime.now()))
            await db.commit()
    except: pass
    return await call_next(request)

# --- 5. API 엔드포인트 ---
@app.post("/register")
async def register(user: UserRegister):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT id FROM users WHERE email = ?", (user.email,)) as cursor:
            if await cursor.fetchone(): raise HTTPException(status_code=400, detail="중복")
        await db.execute("INSERT INTO users (email, hashed_password, name, created_at) VALUES (?, ?, ?, ?)", (user.email, get_password_hash(user.password), user.name, datetime.datetime.now()))
        await db.commit()
    return {"message": "ok"}

@app.post("/login")
async def login(user: UserLogin):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (user.email,)) as cursor:
            u = await cursor.fetchone()
            if not u or not verify_password(user.password, u["hashed_password"]): raise HTTPException(status_code=400, detail="불일치")
            return {"access_token": create_access_token(data={"sub": u["email"]}), "user": {"name": u["name"], "email": u["email"], "level": u["level"]}}

@app.post("/auth/google")
async def auth_google(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={data.get('token')}")
        user_info = resp.json()
    if user_info.get("aud") != GOOGLE_CLIENT_ID: raise HTTPException(status_code=400, detail="오류")
    email = user_info.get("email")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor:
            user = await cursor.fetchone()
            if not user:
                await db.execute("INSERT INTO users (email, name, profile_pic, google_id, created_at) VALUES (?, ?, ?, ?, ?)", (email, user_info.get("name"), user_info.get("picture"), user_info.get("sub"), datetime.datetime.now()))
                await db.commit()
                async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor2: user = await cursor2.fetchone()
    return {"access_token": create_access_token(data={"sub": email}), "user": {"name": user["name"], "email": user["email"], "level": user["level"]}}

@app.get("/admin/users")
async def admin_users(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, email, name, level, created_at FROM users") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.post("/admin/update_user_level")
async def admin_update_level(req: UserLevelRequest, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET level = ? WHERE email = ?", (req.level, req.email))
        await db.commit()
    return {"ok": True}

@app.get("/admin/videos")
async def admin_videos(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, video_id, title, userId, view_count, created_at FROM video_cache ORDER BY id DESC") as cursor: return [dict(r) for r in await cursor.fetchall()]

# --- 6. 다운로드 및 포맷 리스트 ---
@app.get("/video-formats")
async def video_formats(url: str, user=Depends(get_privileged_user)):
    with yt_dlp.YoutubeDL({'quiet': True}) as ydl:
        info = ydl.extract_info(url, download=False)
        formats = [
            {'format_id': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best', 'ext': 'mp4', 'resolution': '최고 화질 MP4', 'note': '자동 변환 및 병합', 'type': 'video'},
            {'format_id': 'bestaudio/best', 'ext': 'mp3', 'resolution': '최고 음질 MP3', 'note': 'MP3로 변환', 'type': 'audio'}
        ]
        for f in info.get('formats', []):
            if f.get('vcodec') != 'none' or f.get('acodec') != 'none':
                formats.append({'format_id': f.get('format_id'), 'ext': f.get('ext'), 'resolution': f.get('resolution') or 'audio', 'filesize': f.get('filesize'), 'note': f.get('format_note') or '', 'type': 'video' if f.get('vcodec') != 'none' else 'audio'})
        return {"formats": formats}

@app.get("/download-file")
async def download_file(url: str, format_id: str, user=Depends(get_privileged_user)):
    temp_dir = tempfile.mkdtemp()
    try:
        is_mp3 = "bestaudio" in format_id or format_id == "mp3"
        ydl_opts = {'format': format_id, 'outtmpl': f'{temp_dir}/d.%(ext)s', 'quiet': True}
        if is_mp3: ydl_opts.update({'postprocessors': [{'key': 'FFmpegExtractAudio','preferredcodec': 'mp3','preferredquality': '192'}]})
        elif "bestvideo" in format_id: ydl_opts.update({'merge_output_format': 'mp4'})
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            title = re.sub(r'[\\/*?:"<>|]', '', info.get('title'))
            f_name = os.listdir(temp_dir)[0]
            actual_path = os.path.join(temp_dir, f_name)
            ext = os.path.splitext(f_name)[1]
            def iterfile():
                with open(actual_path, "rb") as f: yield from f
                shutil.rmtree(temp_dir, ignore_errors=True)
            return StreamingResponse(iterfile(), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(title + ext)}", "Access-Control-Expose-Headers": "Content-Disposition"})
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(e))

# --- 7. 요약 및 스트리밍 ---
@app.post("/smart-subtitles")
async def smart_subtitles(request: VideoRequest, fastapi_request: Request):
    client_ip = fastapi_request.client.host
    url = request.url
    u = await get_current_user(fastapi_request)
    uid = u["email"] if u else "unregistered"
    async def gen():
        m = re.search(r'(?:v=|\/)([0-9A-Za-z_-]{11}).*', url) or re.search(r'youtu\.be\/([0-9A-Za-z_-]{11})', url)
        vid = m.group(1) if m else None
        if vid: yield f"data: {json.dumps({'type': 'video_id', 'value': vid})}\n\n"
        yield f"data: {json.dumps({'type': 'status', 'value': '조회 중...'})}\n\n"
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM video_cache WHERE video_id = ?", (vid,)) as cursor:
                r = await cursor.fetchone()
                if r and r["transcript"] and r["summary"]:
                    await db.execute("UPDATE video_cache SET view_count = view_count + 1 WHERE video_id = ?", (vid,))
                    await db.commit()
                    yield f"data: {json.dumps({'type': 'info', 'title': r['title'], 'video_id': vid})}\n\n"
                    yield f"data: {json.dumps({'type': 'transcript', 'value': r['transcript']})}\n\n"
                    yield f"data: {json.dumps({'type': 'summary_full', 'value': r['summary']})}\n\n"
                    if u and u["level"] in ['admin', 'user2']: yield f"data: {json.dumps({'type': 'can_download', 'url': url})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        yield f"data: {json.dumps({'type': 'status', 'value': '분석 중...'})}\n\n"
        try:
            info = await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL({'quiet': True}).extract_info(url, download=False))
            vid, title = info.get('id'), info.get('title')
            yield f"data: {json.dumps({'type': 'info', 'title': title, 'video_id': vid})}\n\n"
        except Exception as e: yield f"data: {json.dumps({'type': 'error', 'value': str(e)})}\n\n"; return
        content = None
        for l, ia in [('ko', False), ('ko', True), ('en', False), ('en', True)]:
            with tempfile.TemporaryDirectory() as t:
                try:
                    await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL({'skip_download':True,'writesubtitles':not ia,'writeautomaticsub':ia,'subtitleslangs':[l],'outtmpl':f'{t}/s.%(ext)s','quiet':True}).download([url]))
                    content = open(os.path.join(t, os.listdir(t)[0]), 'r', encoding='utf-8').read()
                    if content: break
                except: pass
        if not content: yield f"data: {json.dumps({'type': 'transcript', 'value': '자막 없음'})}\n\n"; yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        yield f"data: {json.dumps({'type': 'status', 'value': 'AI 요약 중...'})}\n\n"
        full = ""
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                async with client.stream("POST", llm_url, headers={'Authorization': f'Bearer {openwebui}'}, json={"model": model_name, "messages": [{"role": "user", "content": f"요약해줘: {content[:8000]}"}], "stream": True}) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            if "[DONE]" in line: break
                            try:
                                txt = json.loads(line[6:])['choices'][0]['delta'].get('content', '')
                                if txt: full += txt; yield f"data: {json.dumps({'type': 'chunk', 'value': txt})}\n\n"
                            except: pass
        except: pass
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO video_cache (video_id, title, userId, request_ip, transcript, summary, created_at, view_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (vid, title, uid, client_ip, content, full, datetime.datetime.now()))
            await db.commit()
        if u and u["level"] in ['admin', 'user2']: yield f"data: {json.dumps({'type': 'can_download', 'url': url})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

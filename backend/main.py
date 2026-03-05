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
from typing import Optional
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# 환경 변수
openwebui = os.getenv('openwebui')
llm_url = os.getenv('llm_url')
model_name = os.getenv('model_name')
SECRET_KEY = os.getenv("SECRET_KEY", "your-very-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app = FastAPI()
DB_PATH = "youtube_cache.db"

# --- 비밀번호 유틸리티 (bcrypt 직접 사용으로 passlib 호환성 문제 해결) ---
def get_password_hash(password: str):
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# --- CORS 설정 (최상단 배치) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://tube.tor-ai.com", "http://localhost:8000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 전역 에러 핸들러 (CORS 보장) ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"서버 내부 오류: {str(exc)}"},
        headers={
            "Access-Control-Allow-Origin": "https://tube.tor-ai.com",
            "Access-Control-Allow-Credentials": "true"
        }
    )

# --- DB 초기화 ---
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS video_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, video_id TEXT UNIQUE, title TEXT, request_ip TEXT, transcript TEXT, summary TEXT, remarks TEXT, created_at TIMESTAMP, view_count INTEGER DEFAULT 1)")
        await db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, hashed_password TEXT, name TEXT, profile_pic TEXT, google_id TEXT, is_admin INTEGER DEFAULT 0, created_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, endpoint TEXT, method TEXT, created_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS ip_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, reason TEXT, created_at TIMESTAMP)")
        
        # 관리자 계정 생성
        admin_id = os.getenv("ADMIN_ID", "yanus")
        admin_pw = os.getenv("ADMIN_PASSWORD", "Yanu1004!")
        async with db.execute("SELECT id FROM users WHERE email = ?", (admin_id,)) as cursor:
            if not await cursor.fetchone():
                admin_hashed = get_password_hash(admin_pw)
                await db.execute("INSERT INTO users (email, hashed_password, name, is_admin, created_at) VALUES (?, ?, ?, ?, ?)", (admin_id, admin_hashed, "최고관리자", 1, datetime.datetime.now()))
        await db.commit()

@app.on_event("startup")
async def startup_event():
    await init_db()

# --- 미들웨어: IP 차단 및 로그 ---
@app.middleware("http")
async def block_ip_and_log(request: Request, call_next):
    client_ip = request.client.host
    if request.method == "OPTIONS":
        return await call_next(request)
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT id FROM ip_blocks WHERE ip = ?", (client_ip,)) as cursor:
                if await cursor.fetchone():
                    return JSONResponse(status_code=403, content={"detail": "차단된 IP"})
            await db.execute("INSERT INTO access_logs (ip, endpoint, method, created_at) VALUES (?, ?, ?, ?)", (client_ip, request.url.path, request.method, datetime.datetime.now()))
            await db.commit()
    except: pass
    
    return await call_next(request)

# --- 모델 ---
class VideoRequest(BaseModel): url: str
class UserRegister(BaseModel): email: str; password: str; name: str
class UserLogin(BaseModel): email: str; password: str
class BlockIPRequest(BaseModel): ip: str; reason: str = ""

# --- 인증 유틸리티 ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): return None
    try:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor: return await cursor.fetchone()
    except: return None

async def get_current_admin(request: Request):
    user = await get_current_user(request)
    if not user or user["is_admin"] != 1: raise HTTPException(status_code=403, detail="관리자 권한 필요")
    return user

# --- API ---
@app.post("/register")
async def register(user: UserRegister):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT id FROM users WHERE email = ?", (user.email,)) as cursor:
            if await cursor.fetchone(): raise HTTPException(status_code=400, detail="이미 존재함")
        await db.execute("INSERT INTO users (email, hashed_password, name, created_at) VALUES (?, ?, ?, ?)", (user.email, get_password_hash(user.password), user.name, datetime.datetime.now()))
        await db.commit()
    return {"message": "ok"}

@app.post("/login")
async def login(user: UserLogin):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (user.email,)) as cursor:
            db_user = await cursor.fetchone()
            if not db_user or not verify_password(user.password, db_user["hashed_password"]):
                raise HTTPException(status_code=400, detail="정보 불일치")
            token = create_access_token(data={"sub": db_user["email"]})
            return {"access_token": token, "user": {"name": db_user["name"], "email": db_user["email"], "picture": db_user["profile_pic"], "is_admin": db_user["is_admin"]}}

@app.post("/auth/google")
async def auth_google(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={data.get('token')}")
        if resp.status_code != 200: raise HTTPException(status_code=400, detail="토큰 오류")
        user_info = resp.json()
    email, name, pic = user_info.get("email"), user_info.get("name"), user_info.get("picture")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor:
            user = await cursor.fetchone()
            if not user:
                await db.execute("INSERT INTO users (email, name, profile_pic, google_id, created_at) VALUES (?, ?, ?, ?, ?)", (email, name, pic, user_info.get("sub"), datetime.datetime.now()))
                await db.commit()
                async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor2: user = await cursor2.fetchone()
    return {"access_token": create_access_token(data={"sub": email}), "user": {"name": name, "email": email, "picture": pic, "is_admin": user["is_admin"] if user else 0}}

@app.get("/admin/users")
async def get_users(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, email, name, is_admin, created_at FROM users") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/admin/videos")
async def get_videos(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, video_id, title, view_count, created_at FROM video_cache") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/admin/logs")
async def get_logs(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 500") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/admin/blocked_ips")
async def get_blocked_ips(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM ip_blocks") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.post("/admin/block_ip")
async def block_ip(req: BlockIPRequest, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO ip_blocks (ip, reason, created_at) VALUES (?, ?, ?)", (req.ip, req.reason, datetime.datetime.now()))
        await db.commit()
    return {"message": "ok"}

@app.delete("/admin/block_ip/{ip}")
async def unblock_ip(ip: str, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM ip_blocks WHERE ip = ?", (ip,))
        await db.commit()
    return {"message": "ok"}

# --- 유튜브 요약 스트리밍 ---
def extract_video_id(url):
    m = re.search(r'(?:v=|\/)([0-9A-Za-z_-]{11}).*', url) or re.search(r'youtu\.be\/([0-9A-Za-z_-]{11})', url)
    return m.group(1) if m else None

async def download_subtitle(url, lang, is_auto):
    with tempfile.TemporaryDirectory() as tmpdir:
        opts = {'skip_download': True, 'writesubtitles': not is_auto, 'writeautomaticsub': is_auto, 'subtitleslangs': [lang], 'outtmpl': f'{tmpdir}/%(id)s.%(ext)s', 'quiet': True}
        try:
            await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL(opts).download([url]))
            files = os.listdir(tmpdir)
            if files:
                with open(os.path.join(tmpdir, files[0]), 'r', encoding='utf-8') as file: return file.read()
        except: pass
    return None

@app.post("/smart-subtitles")
async def smart_subtitles_stream(request: VideoRequest, fastapi_request: Request):
    client_ip = fastapi_request.client.host
    url = request.url
    async def event_generator():
        vid = extract_video_id(url)
        if vid: yield f"data: {json.dumps({'type': 'video_id', 'value': vid})}\n\n"
        yield f"data: {json.dumps({'type': 'status', 'value': '조회 중...'})}\n\n"
        if vid:
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
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        yield f"data: {json.dumps({'type': 'status', 'value': '분석 중...'})}\n\n"
        try:
            info = await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL({'quiet': True}).extract_info(url, download=False))
            vid, title = info.get('id'), info.get('title')
            yield f"data: {json.dumps({'type': 'info', 'title': title, 'video_id': vid})}\n\n"
        except Exception as e: yield f"data: {json.dumps({'type': 'error', 'value': str(e)})}\n\n"; return
        m, a = info.get('subtitles', {}), info.get('automatic_captions', {})
        p = [('ko', False), ('ko', True), ('en', False), ('en', True)]
        content = None
        for l, ia in p:
            if (ia and l in a) or (not ia and l in m):
                content = await download_subtitle(url, l, ia)
                if content: break
        if not content: yield f"data: {json.dumps({'type': 'transcript', 'value': '자막 없음'})}\n\n"; yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        yield f"data: {json.dumps({'type': 'status', 'value': 'AI 요약 중...'})}\n\n"
        full_summary = ""
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                async with client.stream("POST", llm_url, headers={'Authorization': f'Bearer {openwebui}'}, json={"model": model_name, "messages": [{"role": "user", "content": f"요약해줘: {content[:8000]}"}], "stream": True}) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            if "[DONE]" in line: break
                            try:
                                txt = json.loads(line[6:])['choices'][0]['delta'].get('content', '')
                                if txt: full_summary += txt; yield f"data: {json.dumps({'type': 'chunk', 'value': txt})}\n\n"
                            except: pass
        except: pass
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO video_cache (video_id, title, request_ip, transcript, summary, created_at, view_count) VALUES (?, ?, ?, ?, ?, ?, 1)", (vid, title, client_ip, content, full_summary, datetime.datetime.now()))
            await db.commit()
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

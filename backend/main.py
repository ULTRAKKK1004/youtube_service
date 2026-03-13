from fastapi import FastAPI, HTTPException, Request, Depends, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import yt_dlp
import os, tempfile, httpx, aiosqlite, datetime, re, json, asyncio, bcrypt, urllib.parse, shutil, uuid
from typing import Optional
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

# --- 모델 정의 ---
class VideoRequest(BaseModel): url: str
class UserRegister(BaseModel): email: str; password: str; name: str
class UserLogin(BaseModel): email: str; password: str
class PostCreate(BaseModel): title: str; content: str
class PostUpdate(BaseModel): title: str; content: str
class CommentCreate(BaseModel): content: str; parent_id: Optional[int] = None
class UserLevelRequest(BaseModel): email: str; level: str
class BlockIPRequest(BaseModel): ip: str; reason: str = ""

SECRET_KEY = os.getenv("SECRET_KEY", "final-safe-key-1234")
ALGORITHM = "HS256"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
llm_url = os.getenv('llm_url')
openwebui = os.getenv('openwebui')
model_name = os.getenv('model_name')

app = FastAPI()
DB_PATH = "youtube_cache.db"
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR): os.makedirs(UPLOAD_DIR)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# --- 유틸리티 및 인증 ---
def get_password_hash(p): return bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
def verify_password(p, h): 
    try: return bcrypt.checkpw(p.encode('utf-8'), h.encode('utf-8'))
    except: return False
def create_access_token(data):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "): return None
    try:
        payload = jwt.decode(auth_header.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM])
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE email = ?", (payload.get("sub"),)) as cursor: return await cursor.fetchone()
    except: return None

async def get_current_admin(request: Request):
    user = await get_current_user(request)
    if not user or user["level"] != 'admin': raise HTTPException(403, "권한 없음")
    return user

async def get_privileged_user(request: Request):
    user = await get_current_user(request)
    if not user or user["level"] not in ['admin', 'user2']: raise HTTPException(403, "권한 없음")
    return user

# --- DB 초기화 및 미들웨어 ---
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# WebDAV 메서드 등 지원되지 않는 메서드 필터링
INVALID_METHODS = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"}

@app.middleware("http")
async def filter_invalid_methods(request: Request, call_next):
    if request.method in INVALID_METHODS:
        return JSONResponse(status_code=405, content={"detail": "Method Not Allowed"})
    return await call_next(request)

@app.on_event("startup")
async def startup_event():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, hashed_password TEXT, name TEXT, profile_pic TEXT, google_id TEXT, level TEXT DEFAULT 'user', created_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, author_email TEXT, author_name TEXT, author_ip TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, parent_id INTEGER DEFAULT NULL, content TEXT, author_email TEXT, author_name TEXT, author_ip TEXT, created_at TIMESTAMP, FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE)")
        await db.execute("CREATE TABLE IF NOT EXISTS video_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, video_id TEXT UNIQUE, title TEXT, userId TEXT, request_ip TEXT, transcript TEXT, summary TEXT, created_at TIMESTAMP, view_count INTEGER DEFAULT 1)")
        await db.execute("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, endpoint TEXT, method TEXT, created_at TIMESTAMP)")
        await db.execute("CREATE TABLE IF NOT EXISTS ip_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, reason TEXT, created_at TIMESTAMP)")
        await db.commit()

@app.middleware("http")
async def block_ip_and_log(request: Request, call_next):
    if request.method == "OPTIONS": return await call_next(request)
    if request.method in INVALID_METHODS: return JSONResponse(status_code=405, content={"detail": "Method Not Allowed"})
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT id FROM ip_blocks WHERE ip = ?", (request.client.host,)) as cursor:
                if await cursor.fetchone(): return JSONResponse(status_code=403, content={"detail": "차단됨"})
            await db.execute("INSERT INTO access_logs (ip, endpoint, method, created_at) VALUES (?, ?, ?, ?)", (request.client.host, request.url.path, request.method, datetime.datetime.now()))
            await db.commit()
    except: pass
    return await call_next(request)

# --- API 엔드포인트 ---
@app.post("/register")
async def register(user: UserRegister):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT id FROM users WHERE email = ?", (user.email,)) as cursor:
            if await cursor.fetchone(): raise HTTPException(400, "중복")
        await db.execute("INSERT INTO users (email, hashed_password, name, level, created_at) VALUES (?, ?, ?, 'user', ?)", (user.email, get_password_hash(user.password), user.name, datetime.datetime.now()))
        await db.commit()
    return {"ok": True}

@app.post("/login")
async def login(user: UserLogin):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (user.email,)) as cursor:
            u = await cursor.fetchone()
            if not u or not verify_password(user.password, u["hashed_password"]): raise HTTPException(400, "불일치")
            return {"access_token": create_access_token({"sub": u["email"]}), "user": {"name": u["name"], "email": u["email"], "level": u["level"]}}

@app.post("/auth/google")
async def auth_google(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={data.get('token')}")
        uinfo = resp.json()
    if uinfo.get("aud") != GOOGLE_CLIENT_ID: raise HTTPException(400, "오류")
    email = uinfo.get("email")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor:
            u = await cursor.fetchone()
            if not u:
                await db.execute("INSERT INTO users (email, name, profile_pic, google_id, level, created_at) VALUES (?, ?, ?, ?, 'user', ?)", (email, uinfo.get("name"), uinfo.get("picture"), uinfo.get("sub"), datetime.datetime.now()))
                await db.commit()
                async with db.execute("SELECT * FROM users WHERE email = ?", (email,)) as cursor2: u = await cursor2.fetchone()
    return {"access_token": create_access_token({"sub": email}), "user": {"name": u["name"], "email": u["email"], "level": u["level"]}}

@app.get("/posts")
async def get_posts():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, title FROM posts ORDER BY id DESC") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/posts/{pid}")
async def get_post(pid: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM posts WHERE id = ?", (pid,)) as c1:
            p = await c1.fetchone()
            if not p: raise HTTPException(404)
        async with db.execute("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC", (pid,)) as c2:
            cms = [dict(r) for r in await c2.fetchall()]
        return {"post": dict(p), "comments": cms}

@app.post("/posts")
async def create_p(p: PostCreate, request: Request, u=Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.now()
        await db.execute("INSERT INTO posts (title, content, author_email, author_name, author_ip, created_at, updated_at) VALUES (?,?,?,?,?,?,?)", (p.title, p.content, u["email"], u["name"], request.client.host, now, now))
        await db.commit()
    return {"ok": True}

@app.put("/posts/{pid}")
async def update_p(pid: int, p: PostUpdate, u=Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT author_email FROM posts WHERE id = ?", (pid,)) as c:
            existing = await c.fetchone()
            if not existing: raise HTTPException(404)
            if existing["author_email"] != u["email"] and u["level"] != 'admin': raise HTTPException(403)
            await db.execute("UPDATE posts SET title = ?, content = ?, updated_at = ? WHERE id = ?", (p.title, p.content, datetime.datetime.now(), pid))
            await db.commit()
    return {"ok": True}

@app.delete("/posts/{pid}")
async def del_p(pid: int, u=Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT author_email FROM posts WHERE id = ?", (pid,)) as c:
            p = await c.fetchone()
            if not p or (p["author_email"] != u["email"] and u["level"] != 'admin'): raise HTTPException(403)
            await db.execute("DELETE FROM posts WHERE id = ?", (pid,)); await db.commit()
    return {"ok": True}

@app.post("/posts/{pid}/comments")
async def add_cm(pid: int, c: CommentCreate, request: Request, u=Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO comments (post_id, parent_id, content, author_email, author_name, author_ip, created_at) VALUES (?,?,?,?,?,?,?)", (pid, c.parent_id, c.content, u["email"], u["name"], request.client.host, datetime.datetime.now()))
        await db.commit()
    return {"ok": True}

@app.get("/admin/users")
async def admin_u(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, email, name, level, created_at FROM users") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.post("/admin/update_user_level")
async def admin_level(req: UserLevelRequest, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET level = ? WHERE email = ?", (req.level, req.email)); await db.commit()
    return {"ok": True}

@app.get("/admin/videos")
async def admin_v(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, video_id, title, summary, view_count FROM video_cache ORDER BY id DESC") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/admin/logs")
async def admin_logs(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 500") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.get("/admin/blocks")
async def admin_blocks(admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM ip_blocks") as cursor: return [dict(r) for r in await cursor.fetchall()]

@app.post("/admin/block_ip")
async def admin_block(req: BlockIPRequest, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO ip_blocks (ip, reason, created_at) VALUES (?, ?, ?)", (req.ip, req.reason, datetime.datetime.now()))
        await db.commit()
    return {"ok": True}

@app.delete("/admin/block_ip/{ip}")
async def admin_unblock(ip: str, admin=Depends(get_current_admin)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM ip_blocks WHERE ip = ?", (ip,)); await db.commit()
    return {"ok": True}

@app.get("/video-formats")
async def video_f(url: str, user=Depends(get_privileged_user)):
    with yt_dlp.YoutubeDL({'quiet': True}) as ydl:
        info = ydl.extract_info(url, download=False)
        formats = [{'format_id': 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best', 'ext': 'mp4', 'resolution': '최고 화질 MP4'},{'format_id': 'bestaudio/best', 'ext': 'mp3', 'resolution': '최고 음질 MP3'}]
        return {"formats": formats}

@app.get("/download-file")
async def download_f(url: str, format_id: str, user=Depends(get_privileged_user)):
    temp_dir = tempfile.mkdtemp()
    try:
        ydl_opts = {'format': format_id, 'outtmpl': f'{temp_dir}/d.%(ext)s', 'quiet': True}
        if "bestaudio" in format_id: ydl_opts.update({'postprocessors': [{'key': 'FFmpegExtractAudio','preferredcodec': 'mp3','preferredquality': '192'}]})
        elif "bestvideo" in format_id: ydl_opts.update({'merge_output_format': 'mp4'})
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            f_name = os.listdir(temp_dir)[0]; actual_path = os.path.join(temp_dir, f_name)
            def iterfile():
                with open(actual_path, "rb") as f: yield from f
                shutil.rmtree(temp_dir, ignore_errors=True)
            return StreamingResponse(iterfile(), media_type="application/octet-stream", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(info.get('title') + os.path.splitext(f_name)[1])}", "Access-Control-Expose-Headers": "Content-Disposition"})
    except Exception as e: shutil.rmtree(temp_dir, ignore_errors=True); raise HTTPException(400, str(e))

@app.post("/smart-subtitles")
async def smart_sub(request: VideoRequest, fastapi_request: Request):
    client_ip = fastapi_request.client.host; url = request.url; u = await get_current_user(fastapi_request); uid = u["email"] if u else "unregistered"
    async def gen():
        m = re.search(r'(?:v=|\/)([0-9A-Za-z_-]{11}).*', url) or re.search(r'youtu\.be\/([0-9A-Za-z_-]{11})', url)
        vid = m.group(1) if m else None
        if vid: yield f"data: {json.dumps({'type': 'video_id', 'value': vid})}\n\n"
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM video_cache WHERE video_id = ?", (vid,)) as cursor:
                r = await cursor.fetchone()
                if r and r["transcript"] and r["summary"]:
                    await db.execute("UPDATE video_cache SET view_count = view_count + 1 WHERE video_id = ?", (vid,)); await db.commit()
                    yield f"data: {json.dumps({'type': 'chunk', 'value': r['summary']})}\n\n"
                    if u and u["level"] in ['admin', 'user2']: yield f"data: {json.dumps({'type': 'can_download', 'url': url})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        try:
            info = await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL({'quiet': True, 'extractor_args': {'--js-runtimes': 'node'}}).extract_info(url, download=False))
            vid = info.get('id'); yield f"data: {json.dumps({'type': 'video_id', 'value': vid})}\n\n"
        except: yield f"data: {json.dumps({'type': 'error', 'value': '분석 실패'})}\n\n"; return
        content = None
        for l, ia in [('ko', False), ('ko', True), ('en', False), ('en', True)]:
            with tempfile.TemporaryDirectory() as t:
                try:
                    await asyncio.get_event_loop().run_in_executor(None, lambda: yt_dlp.YoutubeDL({'skip_download':True,'writesubtitles':not ia,'writeautomaticsub':ia,'subtitleslangs':[l],'outtmpl':f'{t}/s.%(ext)s','quiet':True}).download([url]))
                    content = open(os.path.join(t, os.listdir(t)[0]), 'r', encoding='utf-8').read(); break
                except: pass
        if not content: yield f"data: {json.dumps({'type': 'done'})}\n\n"; return
        
        # 자막 전송
        yield f"data: {json.dumps({'type': 'transcript', 'value': content})}\n\n"
        
        full = ""
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                async with client.stream("POST", llm_url, headers={'Authorization': f'Bearer {openwebui}'}, json={"model": model_name, "messages": [{"role": "user", "content": f"{content[:]}"}], "stream": True}) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            if "[DONE]" in line: break
                            try:
                                txt = json.loads(line[6:])['choices'][0]['delta'].get('content', '')
                                if txt: full += txt; yield f"data: {json.dumps({'type': 'chunk', 'value': txt})}\n\n"
                            except: pass
        except: pass
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO video_cache (video_id, title, userId, request_ip, transcript, summary, created_at, view_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (vid, info.get('title'), uid, client_ip, content, full, datetime.datetime.now())); await db.commit()
        if u and u["level"] in ['admin', 'user2']: yield f"data: {json.dumps({'type': 'can_download', 'url': url})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

# 📺 YouTube AI 요약기 (YouTube AI Summarizer)

AI를 활용하여 유튜브 영상의 자막을 추출하고 핵심 내용을 실시간으로 요약해주는 웹 애플리케이션입니다.

## ✨ 주요 기능

- **실시간 스트리밍 요약:** AI가 요약 결과를 생성하는 대로 화면에 즉시 출력 (타자 효과).
- **스마트 자막 추출:** 한국어 자막 우선 추출, 없을 경우 영어 또는 자동 생성 자막 활용.
- **SQLite 캐싱:** 동일한 영상에 대한 중복 분석을 방지하여 빠른 결과 제공 및 API 비용 절감.
- **회원 시스템:** 일반 이메일 가입 및 **구글 로그인(OAuth2)** 지원.
- **관리자 대시보드:**
  - 가입 회원 관리 및 권한 확인.
  - 비디오 DB 현황 및 조회수 모니터링.
  - 실시간 접속 로그 확인.
  - **IP 차단 시스템:** 특정 IP 또는 악성 접근 차단 관리.
- **모던한 UI:** 다크 모드 기반의 반응형 디자인 및 분석 단계별 상태 표시.

## 🛠 기술 스택

- **Backend:** Python, FastAPI, uvicorn, aiosqlite, yt-dlp
- **Frontend:** Vanilla JS, HTML5, CSS3, Marked.js (Markdown 렌더링)
- **Database:** SQLite
- **AI:** OpenWebUI 기반 LLM API 연동 (Streaming 지원)

## 🚀 시작하기

### 1. 필수 조건
- Python 3.10 이상
- 유튜브 자막 추출을 위한 `yt-dlp` 라이브러리

### 2. 라이브러리 설치
```bash
pip install fastapi uvicorn yt-dlp aiosqlite bcrypt python-jose[cryptography] authlib httpx python-dotenv python-multipart
```

### 3. 환경 변수 설정 (`backend/.env`)
`backend` 폴더 내에 `.env` 파일을 생성하고 아래 내용을 입력합니다.
```env
# AI API 설정
openwebui=YOUR_API_KEY
llm_url=https://chat.ai-dream.org/api/chat/completions
model_name=summerizer

# 관리자 계정 설정
ADMIN_ID=yanus
ADMIN_PASSWORD=Yanu1004!

# 보안 설정
SECRET_KEY=your_random_secret_key_here

# 구글 로그인 (필요 시)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### 4. 실행 방법

**백엔드 실행 (Port: 8001):**
```bash
cd backend
python main.py
```

**프론트엔드 실행 (Port: 8000):**
```bash
cd frontend
python -m http.server 8000
```

## 📂 폴더 구조
```
yt-dlp-app/
├── backend/
│   ├── main.py            # FastAPI 서버 및 로직
│   ├── .env               # 환경 변수 (Git 제외)
│   └── youtube_cache.db   # SQLite 데이터베이스 (자동 생성)
├── frontend/
│   └── index.html         # 싱글 페이지 웹 앱
├── .gitignore             # Git 업로드 제외 설정
└── README.md              # 프로젝트 문서
```

## ⚠️ 보안 주의사항
- `.env` 파일은 절대 Git에 업로드하지 마세요. (이미 `.gitignore`에 등록됨)
- `SECRET_KEY`는 배포 시 반드시 복잡한 문자열로 변경하세요.
- 실제 서비스 시 HTTPS 환경에서 운영하는 것을 권장합니다.

## 📄 라이선스
이 프로젝트는 개인 학습 및 도구 활용 목적으로 제작되었습니다.

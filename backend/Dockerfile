# Python 3.11 슬림 이미지를 사용합니다.
FROM python:3.11-slim

# 필요한 시스템 패키지(ffmpeg, nodejs 등)를 설치합니다.
RUN apt-get update && apt-get install -y \
    ffmpeg \
    nodejs \
    npm \
    && rm -rf /lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# 종속성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사
COPY . .

# 8001 포트 노출
EXPOSE 8001

# 앱 실행 (main.py 내 uvicorn 실행 로직 사용)
CMD ["python", "main.py"]

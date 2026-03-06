# 경량화된 Nginx 이미지를 사용합니다.
FROM nginx:alpine

# 기본 index.html 파일을 복사합니다.
COPY index.html /usr/share/nginx/html/index.html

# 80 포트를 노출합니다 (내부용)
EXPOSE 80

# Nginx 실행
CMD ["nginx", "-g", "daemon off;"]

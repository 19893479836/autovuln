# ============ 阶段 1：前端构建 ============
FROM node:20-alpine AS fe

WORKDIR /fe

COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund

COPY frontend/index.html ./
COPY frontend/vite.config.js ./
COPY frontend/.eslintrc.cjs ./
COPY frontend/src ./src
RUN npm run build

# ============ 阶段 2：后端运行 ============
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 依赖层缓存
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 业务代码
COPY backend/app ./app
COPY backend/tests ./tests
COPY backend/scripts ./scripts

# 前端产物（由多阶段构建生成，不再依赖仓库中的 dist）
COPY --from=fe /fe/dist /app/frontend/dist

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

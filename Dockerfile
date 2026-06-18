FROM node:22-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
COPY shared /app/shared
RUN npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY shared ./shared
COPY test_rpc_readonly.py test_rpc_trade_flow.py ./
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

RUN python -m py_compile test_rpc_readonly.py test_rpc_trade_flow.py

ENV APP_ENV=production \
    PYTHONPATH=/app/backend

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--app-dir", "backend"]

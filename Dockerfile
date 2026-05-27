# Stage 1 — Build Next.js dashboard
FROM node:20-slim AS dashboard-builder
WORKDIR /dashboard
COPY dashboard/package*.json ./
RUN npm ci --prefer-offline
COPY dashboard/ ./
ENV NEXT_PUBLIC_API_URL=""
RUN npm run build

# Stage 2 — Python backend
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt fastapi uvicorn dilithium-py

COPY engine/ engine/
COPY data/ data/
COPY server.py .

RUN mkdir -p keys certs dashboard/out

# Inject built dashboard static files
COPY --from=dashboard-builder /dashboard/out /app/dashboard/out

EXPOSE 4874

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "4874"]

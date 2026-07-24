# =============================================================================
# Dockerfile — NovaDrive (Modern File Browser)
# =============================================================================

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    zip unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

RUN mkdir -p /data /app/data

ENV ROOT_PATH=/data
ENV USERS_FILE=/app/data/users.json
ENV PORT=8090

EXPOSE 8090

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8090"]

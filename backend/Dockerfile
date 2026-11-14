# Build from the REPOSITORY ROOT so the data pack is inside the image:
#   docker build -f backend/Dockerfile -t orbit-triage .
#   docker run -p 8000:8000 -e LLM_MODE=cloud -e GROQ_API_KEY=... orbit-triage
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/security_triage_data \
    EDGE_PACK_DIR=/app/backend/datasets/edge_cases \
    CACHE_DIR=/tmp/triage-cache \
    LLM_MODE=auto PORT=8000

WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY security_triage_data /app/security_triage_data
COPY backend /app/backend
RUN python scripts/build_edge_pack.py && python -m pytest -q -p no:warnings

RUN useradd --create-home triage && chown -R triage /app
USER triage
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]

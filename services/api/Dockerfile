FROM python:3.12-slim

RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY src/ ./src/

USER 1000:1000

# Bind to 127.0.0.1 only — MUST NOT be 0.0.0.0 (spec: 06-api-control-plane.md §1)
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "127.0.0.1", "--port", "8080"]

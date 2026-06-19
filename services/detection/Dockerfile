FROM python:3.12-slim

RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY src/ ./src/

USER 1000:1000

CMD ["python", "-m", "src.main"]

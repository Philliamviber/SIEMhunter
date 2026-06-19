FROM python:3.12-slim

# Non-root user (UID 1000 matches docker-compose.yml)
RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

# Install dependencies as root before switching user
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Copy application source
COPY src/ ./src/

# Switch to non-root
USER 1000:1000

CMD ["python", "-m", "src.main"]

# SIEMhunter control plane API container.
# FastAPI + uvicorn, bound to 127.0.0.1:8080 only (never 0.0.0.0).
#
# Security invariant: the --host 127.0.0.1 argument in CMD is mandatory.
# Changing it to 0.0.0.0 would expose the unauthenticated health check and
# the control plane to the host LAN. The docker-compose.yml port binding
# ("127.0.0.1:8080:8080") provides a second layer of the same protection.
# Both layers must be in place.

FROM python:3.12-slim

RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY src/ ./src/

USER 1000:1000

# MUST bind to 127.0.0.1 — never 0.0.0.0.
# See instructions/06-api-control-plane.md §1 for the non-negotiable invariant.
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "127.0.0.1", "--port", "8080"]

# SIEMhunter detection service container.
# Compiles Sigma rules to ClickHouse SQL, runs them on a batch cadence,
# attaches ML advisory scores, and writes hits to siemhunter.detection_hits.
#
# Security hardening: see normalization/Dockerfile for rationale.
# Additional note: /app/rules is mounted read-only from the host at runtime
# (see docker-compose.yml). The detection service cannot modify rules.

FROM python:3.12-slim

RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY src/ ./src/

USER 1000:1000

CMD ["python", "-m", "src.main"]

# SIEMhunter normalization service container.
# Polls siemhunter.raw_events, normalizes to OCSF, writes to siemhunter.security_events.
#
# Security hardening:
#   - python:3.12-slim: minimal base image (no dev tools, no shell utilities)
#   - Non-root user (UID 1000 matches docker-compose.yml user: "1000:1000")
#   - --require-hashes: verifies pip package integrity on install (supply chain)
#   - No COPY of secrets: credentials arrive via Docker secrets at /run/secrets/
#   - read_only: true in docker-compose.yml; tmpfs mounts provide writable /tmp

FROM python:3.12-slim

# Create a non-root user. -M: no home directory. -s /sbin/nologin: no shell login.
# UID/GID 1000 must match user: "1000:1000" in docker-compose.yml.
RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

# Install Python dependencies as root (pip needs write access to site-packages).
# --no-cache-dir: reduces image size (no pip cache on disk).
# --require-hashes: verifies each package against its SHA-256 hash in requirements.txt.
#   Any package with a mismatched hash causes the build to fail.
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Copy application source files.
COPY src/ ./src/

# Switch to non-root for all subsequent RUN, CMD, ENTRYPOINT instructions.
USER 1000:1000

CMD ["python", "-m", "src.main"]

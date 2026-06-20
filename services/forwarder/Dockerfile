# SIEMhunter forwarder service container.
# Reads siemhunter.detection_hits and pushes to Sentinel via the Logs Ingestion
# API (DCE/DCR path) and the Incidents API. The only container with egress access.
#
# Why curl is installed: the Docker HEALTHCHECK uses curl to probe the forwarder's
# internal health endpoint. The base python:3.12-slim image does not include curl.
# No other use is made of curl inside the running container.
#
# /app/retry_queue: created here and chown'd so the non-root user can write retry
# files. The directory is also a named Docker volume mount point — Docker Compose
# will mount the volume here, overriding the empty directory created in this step.

FROM python:3.12-slim

# Install curl for the health check probe only.
# --no-install-recommends: prevents pulling in unnecessary packages.
# rm -rf /var/lib/apt/lists/*: cleans up apt cache to reduce image size.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 siemhunter && useradd -u 1000 -g 1000 -s /sbin/nologin -M siemhunter

WORKDIR /app

# Create the retry queue directory and set ownership before switching to non-root.
# The forwarder writes JSON files here for failed batches (on-disk retry queue).
RUN mkdir -p /app/retry_queue && chown 1000:1000 /app/retry_queue

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY src/ ./src/

USER 1000:1000

CMD ["python", "-m", "src.main"]

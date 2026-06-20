# ── Stage 1: Build ───────────────────────────────────────────────────────────
# Uses Node 20 Alpine to install deps and compile the Vite/React app.
# VITE_API_BASE_URL is intentionally empty: the SPA calls /v1/* on the same
# origin, so nginx proxies those requests to the api container.
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first so Docker layer cache survives source-only changes
COPY package*.json ./
RUN npm ci

# Build arg and env must both be set so Vite's import.meta.env substitution
# sees the value at compile time
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

COPY . .
RUN npm run build

# ── Stage 2: Serve ────────────────────────────────────────────────────────────
# Minimal nginx Alpine image; only the compiled dist/ is copied across.
# No Node, no source code, no dev dependencies in the final image.
FROM nginx:1.27-alpine

# Copy compiled assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Drop the default nginx.conf and use ours
COPY nginx.conf /etc/nginx/nginx.conf

# nginx:1.27-alpine already runs the worker processes as the 'nginx' user
# (uid 101, gid 101). The master process starts as root but immediately drops
# privileges. Setting USER here makes the container metadata explicit.
USER 101:101

EXPOSE 8081

CMD ["nginx", "-g", "daemon off;"]

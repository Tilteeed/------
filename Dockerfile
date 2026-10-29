# syntax=docker/dockerfile:1

# No local Node/Python installation is required. Tests run during the VM build.
FROM node:22-alpine3.20 AS frontend-tests
WORKDIR /src
COPY web/agent/ ./web/agent/
COPY tests/ui-state.test.mjs ./tests/ui-state.test.mjs
RUN node --check web/agent/app.js && node --test tests/ui-state.test.mjs

# Reviewed source: Open WebUI v0.12.5, f7ac7ee10962ddec0017f5c29b6740d9b9c5faca.
# Public registry digest verified before adding this file. No moving latest tag.
FROM ghcr.io/open-webui/open-webui:v0.12.5-slim@sha256:9a4db3e6c8d6174d4ed8952304115e90dcc36e9a8b98c2f8984eab321f29505e AS backend-tests
WORKDIR /app/backend
COPY control_plane/ ./control_plane/
COPY scripts/ ./scripts/
COPY tests/ ./platform_tests/
RUN python -m unittest discover -s platform_tests -v

FROM ghcr.io/open-webui/open-webui:v0.12.5-slim@sha256:9a4db3e6c8d6174d4ed8952304115e90dcc36e9a8b98c2f8984eab321f29505e AS runtime
WORKDIR /app/backend
COPY --from=backend-tests /app/backend/control_plane/ ./control_plane/
COPY --from=frontend-tests /src/web/agent/ ./control_plane/static/
COPY scripts/install_integration.py /tmp/install_agent_integration.py
RUN python /tmp/install_agent_integration.py /app/backend/open_webui/main.py \
    && python -m compileall -q /app/backend/control_plane \
    && mkdir -p /app/backend/data \
    && chown -R 1000:0 /app/backend/data /app/backend/control_plane
ENV HOME=/app/backend/data
ENV STATIC_DIR=/app/backend/data/static
USER 1000:0
# Inherit the upstream entrypoint/healthcheck. Startup must still be verified on the VM.

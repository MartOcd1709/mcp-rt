# Scanner image for the docker per-scan backend (hunt.sandbox) and VPS deploys.
#   docker build -t mcp-rt:latest .
#   mcp-rt serve --scan-backend docker        # each scan runs in a fresh `docker run --rm` of this image
FROM python:3.11-slim

# Node (npx-launched MCP servers) + uv/uvx (PyPI/Python MCP servers) + git.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm git curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv && ln -s /root/.local/bin/uvx /usr/local/bin/uvx

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[serve]"

# No ENTRYPOINT: callers pass the full command, e.g. `mcp-rt report --target-stdio "..." --json`
# or `mcp-rt serve --host 0.0.0.0`.

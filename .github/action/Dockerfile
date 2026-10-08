FROM python:3.11-slim

# Node (for npx-launched MCP servers) + uv/uvx (for PyPI/Python MCP servers) + git
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm git curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv && ln -s /root/.local/bin/uvx /usr/local/bin/uvx

# A GitHub Docker action's build context is THIS directory (.github/action/), not the repo root,
# so install mcp-rt from the public repo (pin to a release tag in production, e.g. @v1).
RUN pip install --no-cache-dir "git+https://github.com/MartOcd1709/mcp-rt.git@main"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

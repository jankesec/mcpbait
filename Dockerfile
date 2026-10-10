FROM python:3.11-slim

WORKDIR /app

# Copy repository source code
COPY . /app

# Install package dependencies and mcpbait
RUN pip install --no-cache-dir .

# Initialize default workspace state so mcpbait serve can start headlessly
RUN mcpbait init --dir /app/.mcpbait

# Entrypoint for stdio MCP server transport
ENTRYPOINT ["mcpbait", "serve", "--dir", "/app/.mcpbait"]

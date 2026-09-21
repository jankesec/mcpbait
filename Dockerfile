FROM python:3.11-slim

WORKDIR /app

# Copy repository source code
COPY . /app

# Install package dependencies and mcpbait
RUN pip install --no-cache-dir .

# Entrypoint for stdio MCP server transport
ENTRYPOINT ["mcpbait", "serve"]

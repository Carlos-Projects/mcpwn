FROM python:3.13-slim

RUN groupadd -r mcpwn && useradd -r -g mcpwn -d /app -s /sbin/nologin mcpwn

WORKDIR /app

COPY --chown=mcpwn:mcpwn . .

RUN pip install --no-cache-dir -e ".[dev]" && rm -rf /root/.cache

USER mcpwn

EXPOSE 8080

ENTRYPOINT ["mcpwn"]
CMD ["lab", "--http", "--port", "8080"]
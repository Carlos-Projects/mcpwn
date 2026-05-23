FROM python:3.13-slim

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8080

ENTRYPOINT ["mcpwn"]
CMD ["lab", "--http", "--port", "8080"]
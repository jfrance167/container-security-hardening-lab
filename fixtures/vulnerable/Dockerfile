# Intentionally insecure fixture for static analysis. Do not build or run.
FROM python:latest
ENV API_TOKEN=educational-placeholder-not-a-real-secret
COPY . /app
WORKDIR /app
USER root
CMD ["python", "-m", "http.server", "8080"]

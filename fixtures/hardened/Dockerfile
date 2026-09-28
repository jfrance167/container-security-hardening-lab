# Static fixture only. The digest is an illustrative placeholder, not a deployable image.
FROM python@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
WORKDIR /app
COPY --chown=65532:65532 . /app
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["python", "-c", "import sys; sys.exit(0)"]
CMD ["python", "-m", "http.server", "8080"]

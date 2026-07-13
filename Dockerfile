FROM python:3.12-slim

LABEL org.opencontainers.image.title="HoneyJam" \
      org.opencontainers.image.description="Windows Registry forensics toolkit (RegRipper successor)" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY honeyjam ./honeyjam

RUN pip install --no-cache-dir .

# Analysts mount hives read-only at /data
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["honeyjam"]
CMD ["info"]

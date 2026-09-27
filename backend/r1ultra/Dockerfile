FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy=
WORKDIR /patchwarden
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY REQUIREMENTS.txt .
RUN python -m pip install --no-cache-dir -r REQUIREMENTS.txt
COPY . .
RUN useradd --create-home --uid 10001 patchwarden && mkdir -p /patchwarden/artifacts && chown -R patchwarden:patchwarden /patchwarden
USER patchwarden
CMD ["python","scripts/run_demo.py"]

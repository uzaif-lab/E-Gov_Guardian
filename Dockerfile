# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install minimal build tools (optional; remove if not needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libjpeg-turbo-progs \
    nmap \
    fonts-liberation2 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better build caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn gevent

# Copy the rest of the source code
COPY . .

# Expose Flask default port
EXPOSE 5000

# Launch with Gunicorn (gevent workers for concurrency)
# honour Render’s PORT variable (default 5000 locally)
CMD ["sh", "-c", "gunicorn -k gevent -w ${WEB_CONCURRENCY:-4} -b 0.0.0.0:${PORT:-5000} web_app:app"] 
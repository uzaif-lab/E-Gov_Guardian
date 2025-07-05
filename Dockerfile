# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install minimal build tools (optional; remove if not needed)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better build caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the source code
COPY . .

# Expose Flask default port
EXPOSE 5000

# Launch the web interface
CMD ["python", "start_web_interface.py"] 
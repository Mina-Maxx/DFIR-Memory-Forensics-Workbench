# ==============================================================================
# DFIR Memory Forensics Workbench — Container Image
# Multi-platform Linux container based on Debian/Python 3.11
# ==============================================================================

FROM python:3.11-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000

# Install system dependencies (build-essential, git, libyara, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create necessary directories and non-root user
RUN mkdir -p workspace/dumps workspace/exports workspace/cache logs && \
    groupadd -r dfir && useradd -r -g dfir -d /app -s /bin/bash dfir && \
    chown -R dfir:dfir /app

# Switch to non-root user
USER dfir

# Expose web server port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Run the DFIR web server
CMD ["python", "app.py"]

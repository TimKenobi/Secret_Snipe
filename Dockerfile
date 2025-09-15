# SecretSnipe Dockerfile for Linux Deployment
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # PostgreSQL client
    postgresql-client \
    # Redis client
    redis-tools \
    # Image processing dependencies
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    # PDF processing
    libpoppler-cpp-dev \
    # Git for repository scanning
    git \
    # Build tools
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Create non-root user
RUN useradd --create-home --shell /bin/bash secretsnipe && \
    chown -R secretsnipe:secretsnipe /app
USER secretsnipe

# Copy requirements first for better caching
COPY --chown=secretsnipe:secretsnipe requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY --chown=secretsnipe:secretsnipe . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/cache

# Set permissions
RUN chmod +x /app/docker-entrypoint.sh

# Expose ports
EXPOSE 8050 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from database_manager import init_database; init_database()" || exit 1

# Default command
CMD ["python", "secret_snipe_pg.py", "/scan", "--project", "docker-scan"]
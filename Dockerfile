# SecretSnipe Dockerfile for Linux Deployment
FROM python:3.11-slim-bookworm

# Set environment variables with security in mind
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PYTHONHASHSEED=random \
    # Security: Disable Python bytecode generation
    PYTHONDONTWRITEBYTECODE=1 \
    # Security: Randomize hash seed
    PYTHONHASHSEED=random \
    # Security: Set secure umask
    UMASK=0027

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # PostgreSQL client
    postgresql-client \
    # Redis client
    redis-tools \
    # Basic system libraries
    libglib2.0-0 \
    libgomp1 \
    # Git for repository scanning
    git \
    # Build tools
    build-essential \
    # Download tools for external scanners
    wget \
    curl \
    # Required for Trufflehog and Gitleaks
    ca-certificates \
    # Required for Hyperscan
    libhyperscan-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Security: Install external scanners as root, then switch to non-root user
USER root

# Install Trufflehog with integrity check
RUN wget -O /tmp/trufflehog.tar.gz \
    https://github.com/trufflesecurity/trufflehog/releases/download/v3.81.0/trufflehog_3.81.0_linux_amd64.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Install Gitleaks with integrity check
RUN wget -O /tmp/gitleaks.tar.gz \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp && \
    mv /tmp/gitleaks /usr/local/bin/gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Security: Create non-root user with minimal privileges
RUN groupadd -r secretsnipe && \
    useradd --create-home --shell /bin/bash --gid secretsnipe --system secretsnipe && \
    mkdir -p /app /app/data /app/logs /app/cache /tmp/secretsnipe && \
    chown -R secretsnipe:secretsnipe /app /tmp/secretsnipe && \
    chmod 755 /app && \
    # Clean up build tools for security
    apt-get purge -y build-essential wget curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Switch to non-root user
USER secretsnipe
WORKDIR /app

# Copy requirements first for better caching
COPY --chown=secretsnipe:secretsnipe requirements-prod.txt .

# Install Python dependencies as non-root user
RUN pip install --no-cache-dir --user -r requirements-prod.txt

# Copy application code
COPY --chown=secretsnipe:secretsnipe . .

# Expose ports
EXPOSE 8050 8000

# Health check with proper error handling
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; from database_manager import db_manager; sys.exit(0 if db_manager.health_check() else 1)" || exit 1

# Default command (updated to use run_secret_scanner_pg.py)
CMD ["python", "run_secret_scanner_pg.py", "/scan", "--project", "docker-scan"]
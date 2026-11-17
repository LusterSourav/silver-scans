# Living Threat Intelligence Platform Dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libmaxminddb-dev \
    mmdb-bin \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# geoipupdate is run in separate geoip-updater container
# GeoIP databases are mounted from host at /usr/share/GeoIP

# Create non-root user
RUN groupadd -r livingintel && useradd -r -g livingintel livingintel

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into proper package structure
RUN mkdir -p living_intel
COPY __init__.py platform.py feeds.py plugins.py auto_updater.py live_feeds.py enrichment.py api.py main.py living_intel/
COPY requirements.txt living_intel/
COPY pyproject.toml .
COPY README.md .

# Install package in development mode
RUN pip install -e .

# Create directories
RUN mkdir -p /usr/share/GeoIP /var/log/living_intel /app/data && \
    chown -R livingintel:livingintel /usr/share/GeoIP /var/log/living_intel /app/data

# GeoIP databases are provided by geoip-updater container at runtime

# Switch to non-root user
USER livingintel

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Run application
CMD ["python", "-m", "living_intel.main"]
# Multi-Stage Production Container for Cloud-Ready MiniSOC
FROM python:3.11-slim as base

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose SIEM UI and API ingestion port
EXPOSE 5000

# Healthcheck for container orchestration (Kubernetes, AWS ECS, GCP Cloud Run, Render)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/health || exit 1

# Launch Flask application
CMD ["python", "dashboard/app.py"]

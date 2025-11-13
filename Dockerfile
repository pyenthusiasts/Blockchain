# Dockerfile for Blockchain application
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Install the package
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/wallets

# Set permissions
RUN chmod +x cli/blockchain_cli.py

# Expose port for future API
EXPOSE 5000

# Set default command
CMD ["python", "-m", "examples.basic_usage"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "from blockchain_core import Blockchain; bc = Blockchain(); print('healthy' if bc.is_valid_chain() else 'unhealthy')"

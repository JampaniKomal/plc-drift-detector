FROM python:3.10-slim

WORKDIR /app

# Install system dependencies if any needed for lxml
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev libxslt-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY engine/ ./engine/
COPY ui/ ./ui/
COPY tools/ ./tools/

# Create logs directory
RUN mkdir -p /app/logs

ENV PYTHONPATH=/app

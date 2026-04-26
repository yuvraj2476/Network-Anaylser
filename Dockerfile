FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY network_manager.py .
COPY templates/ ./templates/

# Expose the Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=network_manager.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "network_manager.py"]

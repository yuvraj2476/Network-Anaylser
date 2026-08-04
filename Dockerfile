FROM python:3.11-slim

WORKDIR /app

# System deps: wireless tools + packet capture + go (optional - for subfinder/assetfinder/httpx)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iw wireless-tools iproute2 net-tools wireless-regdb \
    procps curl iputils-ping wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY network_manager.py .
COPY templates/ ./templates/
COPY docs/ ./docs/

RUN mkdir -p /app/pcaps /app/data

ENV DB_PATH=/app/data/network_manager.db
ENV PCAP_DIR=/app/pcaps
ENV FLASK_APP=network_manager.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "network_manager.py"]

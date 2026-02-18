FROM python:3.11-slim

# Install system dependencies for scapy and pcap
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Set environment variables with defaults
ENV ELASTIC_URL=http://elasticsearch:9200
ENV ELASTIC_INDEX=pcap-packets-*

# Run the application
CMD ["python", "pcap-reader.py"]

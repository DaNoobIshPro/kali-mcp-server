# Use Kali Linux rolling as base for security tools
FROM kalilinux/kali-rolling:latest

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Update and install required tools
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    sqlmap \
    wpscan \
    dirb \
    exploitdb \
    ettercap-text-only \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Update exploitdb database (searchsploit comes with exploitdb)
RUN searchsploit -u || true

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy the server code
COPY kali_server.py .

# Create non-root user with necessary capabilities
RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Run the server
CMD ["python3", "kali_server.py"]
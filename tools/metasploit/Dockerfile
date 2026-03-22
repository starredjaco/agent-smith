FROM metasploitframework/metasploit-framework:latest

USER root

# Metasploit image is Alpine-based — use apk
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir flask --break-system-packages

# Command API server — same pattern as kali-server-mcp
COPY server.py /opt/server.py

EXPOSE 5000

# Start the Flask API server (msfconsole is invoked per-command)
CMD ["python3", "/opt/server.py"]

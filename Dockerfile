FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y wget curl apt-transport-https ca-certificates gnupg lsb-release

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy

WORKDIR /app

# Create directories for reports
RUN mkdir -p /app/grype /app/trivy

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application files
COPY . .

# Create a non-root user for security with home directory
RUN groupadd -r appuser && useradd -r -g appuser -m -d /home/appuser appuser

# Create Trivy and Grype cache directories with proper permissions
RUN mkdir -p /home/appuser/.cache/trivy /home/appuser/.cache/grype && \
    chown -R appuser:appuser /home/appuser

# Ensure proper permissions for mounted directories and change ownership
RUN chmod -R 777 /app/grype /app/trivy && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

CMD ["python", "scan_api.py"]

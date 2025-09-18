# Use Python 3.11 Alpine for smaller image size
FROM python:3.11-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for MySQL client
RUN apk add --no-cache \
    gcc \
    musl-dev \
    mariadb-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    curl

# Copy requirements first for better Docker layer caching
COPY Server/requirements.txt ./requirements.txt
# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY Server ./Server

# Create config directory
RUN mkdir -p /config

# Set environment variables
ENV PYTHONPATH=/app
ENV CONFIG_DIR=/config
ENV PASSWORD_POLICY_FILE=password_policy.yaml
ENV DOCKER_ENV=true

# Database environment variables
ENV DB_HOST=db
ENV DB_PORT=3306
ENV DB_USER=my_user
ENV DB_PASSWORD=my_password
ENV DB_NAME=CommunicationLTD

# Email configuration (for production, set these in docker-compose or secrets)
ENV SMTP_SERVER=smtp.gmail.com
ENV SMTP_PORT=587
ENV USE_TLS=true
ENV SENDER_EMAIL=noreply@communicationltd.com
ENV SENDER_NAME="Communication LTD"
# ENV SENDER_PASSWORD=your_email_app_password  # Set this in docker-compose.yml

# Create non-root user for security
RUN adduser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /app /config
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -fsS http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start command
CMD ["uvicorn", "Server.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

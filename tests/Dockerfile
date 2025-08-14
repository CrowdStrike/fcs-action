# Use an outdated base image with known vulnerabilities
FROM ubuntu:18.04

# Deprecated instruction (Docker best practice violation)
MAINTAINER test@example.com

# Hardcode sensitive information in environment variables
ENV DATABASE_PASSWORD=admin123
ENV API_KEY=sk-1234567890abcdef
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV JWT_SECRET=super-secret-jwt-key

# Run as root user (security risk - should drop privileges)
USER root

# Install basic packages and create insecure setup
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create sensitive files with secrets
RUN mkdir -p /app && \
    echo "database_url=mysql://admin:password123@localhost/prod" > /app/.env && \
    echo "stripe_key=sk_live_1234567890abcdef" >> /app/.env && \
    echo "github_token=ghp_abcdef1234567890" >> /app/.env

# Set insecure file permissions
RUN chmod 777 /app

# Create a fake SSH private key
RUN mkdir -p /root/.ssh && \
    echo "-----BEGIN PRIVATE KEY-----" > /root/.ssh/id_rsa && \
    echo "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..." >> /root/.ssh/id_rsa && \
    echo "fake-private-key-content-for-testing" >> /root/.ssh/id_rsa && \
    echo "-----END PRIVATE KEY-----" >> /root/.ssh/id_rsa

# Expose unnecessary ports
EXPOSE 22 3306 5432

# Set working directory with broad permissions
WORKDIR /app

# Use shell form of CMD (potential security risk)
CMD echo "Application started" && sleep infinity

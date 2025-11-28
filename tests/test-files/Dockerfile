# Use an insecure base image
FROM ubuntu:latest

# Running as root (default) - security issue
USER root

# Installing packages without pinning versions
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ssh

# Hardcoded secrets - security issue
ENV API_KEY="hardcoded-api-key-12345"
ENV DATABASE_URL="mysql://root:password123@localhost:3306/mydb"

# Exposing sensitive ports
EXPOSE 22 3306 5432

# Running SSH daemon - potential security issue
RUN systemctl enable ssh

# Copy everything including potentially sensitive files
COPY . /app

WORKDIR /app

# Running application as root
CMD ["/bin/bash", "-c", "service ssh start && python app.py"]

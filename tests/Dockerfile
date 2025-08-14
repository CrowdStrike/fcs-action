# Use an outdated Ubuntu base image with known vulnerabilities
FROM ubuntu:18.04

# Set maintainer (deprecated instruction)
MAINTAINER test@example.com

# Run as root user (security risk)
USER root

# Install packages (security risk: not updating first, installing vulnerable versions)
RUN apt-get update && apt-get install -y \
    # Install potentially vulnerable packages
    curl \
    wget \
    openssh-server \
    apache2 \
    mysql-server \
    # Install unnecessary packages
    telnet \
    ftp \
    # Install packages with --allow-unauthenticated (insecure)
    && apt-get install -y --allow-unauthenticated some-package || true

# Hardcode sensitive information
ENV DATABASE_PASSWORD=admin123
ENV API_KEY=sk-1234567890abcdef
ENV AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Create user with weak password and add to sudoers
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:password123' | chpasswd && \
    usermod -aG sudo testuser

# Set insecure file permissions
RUN chmod 777 /etc/passwd && \
    chmod 777 /etc/shadow && \
    chmod 777 /tmp

# Create sensitive files directly in image (simulate accidental inclusion)
RUN mkdir -p /root/.ssh && \
    echo "-----BEGIN OPENSSH PRIVATE KEY-----" > /root/.ssh/id_rsa && \
    echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn" >> /root/.ssh/id_rsa && \
    echo "NhAAAAAwEAAQAAAQEAtest-fake-private-key-for-vulnerability-testing-do-not-use-in-production" >> /root/.ssh/id_rsa && \
    echo "This is a fake SSH private key for testing vulnerability detection." >> /root/.ssh/id_rsa && \
    echo "Never use this in production environments." >> /root/.ssh/id_rsa && \
    echo "-----END OPENSSH PRIVATE KEY-----" >> /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

RUN mkdir -p /app && \
    echo "# Environment file with sensitive information - DO NOT USE IN PRODUCTION" > /app/.env && \
    echo "DATABASE_URL=mysql://admin:password123@localhost:3306/production_db" >> /app/.env && \
    echo "POSTGRES_PASSWORD=super_secret_password" >> /app/.env && \
    echo "JWT_SECRET=my-super-secret-jwt-key-that-should-never-be-hardcoded" >> /app/.env && \
    echo "API_TOKEN=abc123def456ghi789" >> /app/.env && \
    echo "STRIPE_SECRET_KEY=sk_test_1234567890abcdef" >> /app/.env && \
    echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> /app/.env && \
    echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /app/.env && \
    echo "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz" >> /app/.env && \
    echo "ADMIN_PASSWORD=admin" >> /app/.env && \
    echo "ROOT_PASSWORD=toor" >> /app/.env

RUN echo "-- Database backup with sensitive data - DO NOT USE IN PRODUCTION" > /tmp/database_backup.sql && \
    echo "CREATE DATABASE IF NOT EXISTS production_db;" >> /tmp/database_backup.sql && \
    echo "USE production_db;" >> /tmp/database_backup.sql && \
    echo "CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(50), password VARCHAR(255), email VARCHAR(100), ssn VARCHAR(11), credit_card VARCHAR(20));" >> /tmp/database_backup.sql && \
    echo "INSERT INTO users (username, password, email, ssn, credit_card) VALUES ('admin', 'admin', 'admin@company.com', '123-45-6789', '4111-1111-1111-1111');" >> /tmp/database_backup.sql && \
    echo "INSERT INTO users (username, password, email, ssn, credit_card) VALUES ('root', 'toor', 'root@company.com', '987-65-4321', '5555-5555-5555-4444');" >> /tmp/database_backup.sql && \
    echo "-- Production database password: prod_db_pass_2024!" >> /tmp/database_backup.sql && \
    echo "-- Admin panel: https://admin.company.com (admin/secret123)" >> /tmp/database_backup.sql

# Install pip packages with potentially vulnerable versions (insecure: --trusted-host)
RUN apt-get install -y python3-pip && \
    pip3 install --trusted-host pypi.org --trusted-host pypi.python.org \
    Django==2.2.0 \
    Pillow==7.1.0 \
    requests==2.22.0 \
    pyyaml==5.3.1 \
    jinja2==2.11.0 || echo "Some packages may have failed to install"

# Expose unnecessary ports
EXPOSE 22 23 25 53 80 135 139 443 445 993 995 1433 3306 3389 5432 5900

# Download and execute script from internet (insecure)
RUN curl -sSL https://get.docker.com/ | sh || true

# Add vulnerable Node.js application
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g express@4.16.0 lodash@4.17.4 moment@2.19.3 || echo "Some npm packages may have failed"

# Create directory with world-writable permissions  
RUN mkdir -p /app/uploads && chmod 777 /app/uploads

# Install Java (potentially vulnerable version available in Ubuntu 18.04)
RUN apt-get install -y openjdk-8-jdk || apt-get install -y default-jdk

# Configure SSH with insecure settings
RUN mkdir -p /var/run/sshd && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config && \
    echo 'X11Forwarding yes' >> /etc/ssh/sshd_config

# Set up a web server with directory listing enabled
RUN echo 'Options +Indexes' > /var/www/html/.htaccess && \
    a2enmod userdir

# Install packages that are commonly flagged for vulnerabilities
RUN apt-get install -y \
    bind9 \
    postfix \
    dovecot-core \
    proftpd-basic \
    vsftpd

# Create startup script that runs multiple services as root
RUN echo '#!/bin/bash\n\
service ssh start\n\
service apache2 start\n\
service mysql start\n\
service bind9 start\n\
service postfix start\n\
/bin/bash' > /start.sh && chmod +x /start.sh

# Set working directory with broad permissions
WORKDIR /app
RUN chmod 777 /app

# Don't drop privileges - continue running as root
# USER root (explicitly staying as root)

# Use shell form of CMD (potential security risk)
CMD /start.sh

# Add health check that could expose information
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/server-status || exit 1

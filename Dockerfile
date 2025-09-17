# Base image (Python 3.8 slim) – can update later to reduce vulnerabilities
FROM python:3.8-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements file and install dependencies
# Pin versions in requirements.txt later to reduce vulnerabilities
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Expose port for Flask app
EXPOSE 8080

# Default command to run the app
CMD ["python", "app.py"]

# Notes:
# 1. Consider scanning this image periodically for new vulnerabilities.
# 2. Python base image may contain low-severity CVEs; can replace or pin minor version.

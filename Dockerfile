
# Use Python 3.11 slim image
FROM python:3.13.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy model artifacts
COPY ["model.bin", "dv.bin", "scaler.bin", "./"]

# Copy application code
COPY serve.py .

# Expose port
EXPOSE 9696

# Run the application
ENTRYPOINT ["python", "serve.py"]

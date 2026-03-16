# Backend Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy backend code
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose master TCP server port
EXPOSE 5000

# Command to run the backend
CMD ["python", "main.py"]

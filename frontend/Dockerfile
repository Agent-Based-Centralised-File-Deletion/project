# Frontend Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy frontend code
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 5000

# Command to run the frontend
CMD ["python", "app.py"]
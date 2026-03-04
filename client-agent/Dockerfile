# Client-Agent Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy client-agent code
COPY . .

# Create an empty requirements.txt file
RUN touch requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Command to run the client-agent
CMD ["python", "agent.py"]
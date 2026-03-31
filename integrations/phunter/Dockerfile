FROM python:3.12-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git

# Clone Phunter
RUN git clone https://github.com/N0rz3/Phunter.git /app/Phunter

# Set working directory
WORKDIR /app

# Add uv
COPY --from=ghcr.io/astral-sh/uv:0.11.1 /uv /uvx /bin/

# Copy requirements file and app.py to the working directory
COPY requirements.txt app.py ./

# Use uv for faster dependency installation
RUN uv pip install --system --no-cache-dir -r requirements.txt -r /app/Phunter/requirements.txt

# Expose port
EXPOSE 5612

# Run the app
CMD ["python", "app.py"]
FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for snarkjs
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Node deps for ZKP circuits
COPY identity/circuits/package.json identity/circuits/
RUN cd identity/circuits && npm install --production

# Copy source
COPY . .

# Create data directory
RUN mkdir -p data logs

EXPOSE 5001

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "network/node.py"]
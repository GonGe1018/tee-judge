# TEE-Judge Server
FROM python:3.11-slim

WORKDIR /app

# Install GCC for compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY server-requirements.txt .
RUN pip install --no-cache-dir -r server-requirements.txt

# Create non-root user
RUN useradd -m -s /bin/bash appuser

# Copy application
COPY app/ ./app/
COPY frontend/ ./frontend/
COPY data/problems/ ./data/problems/
COPY scripts/gen_testcases.py ./scripts/gen_testcases.py

# Own data dir
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ==============================================================================
# Stage 1: Build virtualenv and compile dependencies
# ==============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies required for compiling C extensions (psycopg2, cryptography, argon2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ==============================================================================
# Stage 2: Final runtime image
# ==============================================================================
FROM python:3.11-slim AS runner

# Install runtime PostgreSQL client libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root group and user
RUN groupadd -r -g 1001 appgroup && \
    useradd -r -u 1001 -g appgroup -d /app -s /sbin/nologin appuser

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UPLOAD_FOLDER=/var/secure_files

WORKDIR /app

# Prepare upload directory and set permissions
RUN mkdir -p /var/secure_files /app && \
    chown -R appuser:appgroup /var/secure_files /app

# Copy application files with appropriate ownership
COPY --chown=appuser:appgroup . /app

# Switch to non-root user
USER appuser

EXPOSE 5000

# Container healthcheck using the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

# Run the application via gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]

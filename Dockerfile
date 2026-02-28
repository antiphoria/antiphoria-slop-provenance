FROM python:3.12-slim

WORKDIR /app

# Install pinned dependencies for deterministic builds
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Install the package (no-deps: already in requirements.txt)
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir --no-deps .

# Run as non-root to limit impact of dependency vulnerabilities
RUN useradd -m slopuser && chown -R slopuser:slopuser /app
USER slopuser

CMD ["slop-cli", "--help"]

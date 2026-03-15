FROM python:3.12-slim

WORKDIR /app

# Install the package
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir .

# Run as non-root to limit impact of dependency vulnerabilities
RUN useradd -m slopuser && chown -R slopuser:slopuser /app
USER slopuser

CMD ["slop-cli", "--help"]

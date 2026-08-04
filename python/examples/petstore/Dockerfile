FROM python:3.12-slim
WORKDIR /app
# Build context must be python/ (the parent SDK dir), not this directory --
# keyorix.py lives one level up from examples/petstore/, and Docker COPY
# can't reference paths outside the build context. See docker-compose.yml's
# context: ../.. for the working invocation.
COPY examples/petstore/requirements.lock.txt .
# --require-hashes: requirements.lock.txt is a hash-pinned lock (via
# pip-compile --generate-hashes, verified against the actual resolved
# wheel), not just a version range -- pip refuses to install anything
# whose downloaded artifact doesn't match one of the pinned hashes.
RUN pip install --no-cache-dir --only-binary :all: --require-hashes -r requirements.lock.txt
COPY keyorix.py .
COPY examples/petstore/main.py .
RUN useradd --no-create-home --shell /bin/false appuser \
    && chown -R appuser /app
USER appuser
EXPOSE 3002
CMD ["python", "main.py"]

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary :all: -r requirements.txt
COPY ../../keyorix.py ./keyorix.py
COPY main.py .
RUN useradd --no-create-home --shell /bin/false appuser \
    && chown -R appuser /app
USER appuser
EXPOSE 3002
CMD ["python", "main.py"]

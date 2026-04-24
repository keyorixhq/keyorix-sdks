FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ../../keyorix.py ./keyorix.py
COPY main.py .
EXPOSE 3002
CMD ["python", "main.py"]

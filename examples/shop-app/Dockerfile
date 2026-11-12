# DELIBERATELY INSECURE demo: old base image, runs as root.
FROM python:3.9.0-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]

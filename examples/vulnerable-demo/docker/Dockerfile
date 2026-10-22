# DELIBERATELY INSECURE: demo for polyscan, do not copy.
FROM python:latest
ADD . /app
ENV DB_PASSWORD=supersecret
RUN curl -fsSL https://example.org/install.sh | sh
RUN chmod -R 777 /app
RUN pip install flask
EXPOSE 22
CMD ["python", "/app/app.py"]

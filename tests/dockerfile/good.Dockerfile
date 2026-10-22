# ok: polyscan-dockerfile-base-image-not-pinned
FROM python:3.12.7-slim
# ok: polyscan-dockerfile-add-instead-of-copy
COPY . /app
RUN useradd --create-home app
# a USER instruction somewhere means the image does not run as root
# ok: polyscan-dockerfile-runs-as-root
USER app
CMD ["python", "/app/app.py"]

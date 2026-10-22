# Demo: an old base image. Images get vulnerabilities over time; this one is long out of date.
FROM python:3.9.0
USER nobody
CMD ["python", "--version"]

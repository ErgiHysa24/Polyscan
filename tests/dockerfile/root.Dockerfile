# ruleid: polyscan-dockerfile-runs-as-root
FROM python:3.12.7-slim
RUN pip install flask
# USER root is still root
USER root

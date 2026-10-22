# ruleid: polyscan-dockerfile-base-image-not-pinned
FROM python:latest AS build
# ruleid: polyscan-dockerfile-add-instead-of-copy
ADD . /src
# ok: polyscan-dockerfile-add-instead-of-copy
ADD https://example.org/tool.sh /tool.sh
# ok: polyscan-dockerfile-add-instead-of-copy
ADD vendor.tar.gz /opt
# ruleid: polyscan-dockerfile-add-instead-of-copy
ADD --chown=app:app config /etc/app
# ruleid: polyscan-dockerfile-pipe-to-shell
RUN curl -fsSL https://example.org/install.sh | sh
# ok: polyscan-dockerfile-pipe-to-shell
RUN curl -fsSLo /tmp/install.sh https://example.org/install.sh && sha256sum -c checks.txt
# ruleid: polyscan-dockerfile-chmod-777
RUN chmod -R 777 /app
# ok: polyscan-dockerfile-chmod-777
RUN chmod 755 /app/run.sh

# ok: polyscan-dockerfile-base-image-not-pinned
FROM build AS test
# ok: polyscan-dockerfile-base-image-not-pinned
FROM --platform=linux/amd64 build AS other
# several references to stages: none of them is an untagged image
# ok: polyscan-dockerfile-base-image-not-pinned
FROM build AS third
# ok: polyscan-dockerfile-base-image-not-pinned
FROM other
# ruleid: polyscan-dockerfile-base-image-not-pinned
FROM redis
# ok: polyscan-dockerfile-base-image-not-pinned
FROM scratch
# ok: polyscan-dockerfile-base-image-not-pinned
FROM nginx@sha256:0123456789abcdef
# ok: polyscan-dockerfile-base-image-not-pinned
FROM python:3.12.7-slim
# ruleid: polyscan-dockerfile-runs-as-root
FROM node:20.17.0

# ruleid: polyscan-dockerfile-hardcoded-secret
ENV DB_PASSWORD=supersecret
# ruleid: polyscan-dockerfile-hardcoded-secret
ENV API_TOKEN abc123
# ruleid: polyscan-dockerfile-hardcoded-secret
ARG SECRET_KEY="abc"
# ok: polyscan-dockerfile-hardcoded-secret
ARG BUILD_TOKEN
# ok: polyscan-dockerfile-hardcoded-secret
ENV DB_PASSWORD=${DB_PASSWORD}
# ok: polyscan-dockerfile-hardcoded-secret
ENV DB_PASSWORD_FILE=/run/secrets/db_password
# ok: polyscan-dockerfile-hardcoded-secret
ENV APP_MODE=production

# ruleid: polyscan-dockerfile-ssh-port
EXPOSE 22
# ruleid: polyscan-dockerfile-ssh-port
EXPOSE 80 22/tcp
# ok: polyscan-dockerfile-ssh-port
EXPOSE 8022 2222 5432

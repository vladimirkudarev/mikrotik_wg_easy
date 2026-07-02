FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client qrencode ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/app app

WORKDIR /app
COPY src/ /app/src/
COPY README.md /app/README.md

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8080 \
    APP_DATA=/data \
    ROS_HOST=172.17.0.1 \
    ROS_USER=wg-easy \
    ROS_SSH_KEY=/data/id_ed25519 \
    APP_TRUST_PROXY_HEADERS=0

VOLUME ["/data"]
EXPOSE 8080

USER app
CMD ["python3", "/app/src/mikrotik_wg_easy/app.py"]

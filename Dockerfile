FROM python:3.12-alpine

RUN apk add --no-cache ca-certificates openssh-client-default libqrencode-tools su-exec \
    && addgroup -S app \
    && adduser -S -D -h /home/app -G app -u 10001 app \
    && mkdir -p /home/app /data \
    && chown -R app:app /home/app /data

WORKDIR /app
COPY src/ /app/src/
COPY README.md /app/README.md
COPY scripts/container-entrypoint.sh /app/container-entrypoint.sh
RUN chmod +x /app/container-entrypoint.sh

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8080 \
    APP_DATA=/data \
    ROS_HOST=172.17.0.1 \
    ROS_USER=wg-easy \
    ROS_SSH_KEY=/data/id_ed25519 \
    APP_TRUST_PROXY_HEADERS=0

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/app/container-entrypoint.sh"]
CMD ["python3", "/app/src/mikrotik_wg_easy/app.py"]

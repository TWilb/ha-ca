ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-cryptography

COPY app /app
WORKDIR /app

CMD ["python3", "-u", "/app/server.py"]

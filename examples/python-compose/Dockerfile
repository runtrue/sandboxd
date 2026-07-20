FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

RUN ln -s /usr/local/bin/python3 /usr/bin/python3

COPY server.py client.py health.py limits.py snapshot_client.py snapshot_health.py /app/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65534:65534
WORKDIR /work
ENTRYPOINT ["/usr/bin/python3"]

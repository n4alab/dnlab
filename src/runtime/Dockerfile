# syntax=docker/dockerfile:1.7
ARG RUNTIME_BASE=python:3.13-slim
FROM ${RUNTIME_BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/dnlab-runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY setup.py pyproject.toml ./
COPY dnlab_runtime ./dnlab_runtime
RUN pip install --no-cache-dir .
ENTRYPOINT ["dnlab-runtime"]
CMD ["serve"]

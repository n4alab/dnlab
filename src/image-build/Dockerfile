# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOCKER_BUILDKIT=1 \
    DNLAB_IMAGE_BUILD_WORKSPACE=/var/lib/dnlab-image-build

WORKDIR /opt/dnlab-image-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        bzip2 \
        docker-buildx \
        docker-cli \
        docker.io \
        git \
        libguestfs-tools \
        linux-image-amd64 \
        make \
        openssl \
        qemu-utils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi==0.115.12 uvicorn[standard]==0.34.0 pydantic==2.11.1 python-multipart==0.0.20

COPY . .
RUN chmod +x /opt/dnlab-image-build/build_image.py /opt/dnlab-image-build/apply.py \
    && mkdir -p /usr/share/doc/dnlab/third-party \
    && printf '%s\n' \
        '# dNLab Third-Party Notices' \
        '' \
        'This image contains dNLab image-build tools plus Debian packages, Docker CLI packages and Python dependencies.' \
        'Release builds must attach a generated SBOM and full notice bundle for the exact image tag.' \
        'Images generated from upstream NOS, vrnetlab or FRR images need their own derived-image notices if redistributed.' \
        > /usr/share/doc/dnlab/third-party/THIRD_PARTY_NOTICES.md

VOLUME ["/var/lib/dnlab-image-build", "/opt/vrnetlab"]
EXPOSE 8082
CMD ["python", "/opt/dnlab-image-build/api.py"]

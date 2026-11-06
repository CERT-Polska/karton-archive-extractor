FROM python:3.12
SHELL ["/bin/bash", "-c"]

# Native unpackers that sflock shells out to (formats beyond 7-Zip
# and zipjail-handled ones): RAR, ACE, CAB, lzip, zpaq
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y \
    rar \
    unace \
    cabextract \
    lzip \
    zlib1g-dev \
    zpaq \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG SEVENZIP_VERSION=26.05
ARG SEVENZIP_SHA256=22cf82fcc6eb7474f1d5bb4f02c0f8ebd573a718089d6833dc30f8350a3b232e
RUN curl -fsSL -o /tmp/7z.tar.xz \
        "https://github.com/ip7z/7zip/releases/download/${SEVENZIP_VERSION}/7z${SEVENZIP_VERSION/./}-linux-x64.tar.xz" \
    && echo "${SEVENZIP_SHA256}  /tmp/7z.tar.xz" | sha256sum -c - \
    && mkdir -p /tmp/7z-dist \
    && tar -xJf /tmp/7z.tar.xz -C /tmp/7z-dist \
    && install -m 0755 /tmp/7z-dist/7zzs /usr/local/bin/7zz \
    && /usr/local/bin/7zz i >/dev/null \
    && rm -rf /tmp/7z.tar.xz /tmp/7z-dist


WORKDIR /app/service
COPY ./requirements.txt ./requirements-debloat.txt ./
RUN pip install -r requirements.txt
RUN pip install --no-deps -r requirements-debloat.txt
COPY ./README.md ./README.md
COPY ./MANIFEST.in ./MANIFEST.in
COPY ./karton ./karton
COPY ./setup.py ./setup.py
RUN pip install .
ENTRYPOINT karton-archive-extractor

FROM python:3.12
SHELL ["/bin/bash", "-c"]

# Install 7zip from unstable (no patch for CVE-2026-14266 on stable branch for Debian Trixie)
# Remove this line and add 7zip to the second apt invocation after stable 7z is fixed
RUN echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends 7zip/unstable && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm /etc/apt/sources.list.d/unstable.list

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

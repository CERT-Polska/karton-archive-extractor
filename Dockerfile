FROM python:3.12
SHELL ["/bin/bash", "-c"]
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y \
    p7zip-full \
    rar \
    unace \
    cabextract \
    lzip \
    zlib1g-dev \
    zpaq

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

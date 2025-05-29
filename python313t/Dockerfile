FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    wget \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libffi-dev \
    liblzma-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libedit-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHON_VERSION=3.13.3
WORKDIR /opt

RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz \
    && tar -xf Python-${PYTHON_VERSION}.tar.xz

WORKDIR /opt/Python-${PYTHON_VERSION}
RUN ./configure --prefix=/usr/local/python3.13nogil --disable-gil --with-ensurepip=install \
    && make -j$(nproc) \
    && make altinstall

RUN ln -s /usr/local/python3.13nogil/bin/python3.13 /usr/local/bin/python3.13 && \
    ln -s /usr/local/python3.13nogil/bin/pip3.13 /usr/local/bin/pip3.13

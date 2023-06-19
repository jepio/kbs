FROM mcr.microsoft.com/devcontainers/rust:0-1-bullseye

ENV DEBIAN_FRONTEND noninteractive

# Install Build Dependencies
RUN apt-get update && apt-get install -y apt-utils
RUN apt-get install -y \
    clang \
    cmake \
    curl \
    gnupg \
    libclang-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    pkg-config \
    protobuf-compiler \
    wget
RUN wget https://go.dev/dl/go1.20.1.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install TPM Build Dependencies
RUN apt-get install -y --no-install-recommends libtss2-dev

# Install TDX Build Dependencies
RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify-dev \
    libtdx-attest-dev
# Use an official image with g++, cmake, and other build tools
FROM ubuntu:20.04

# Install necessary packages: build-essential, cmake, protobuf, gRPC, GTest, and dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    libgtest-dev \
    g++ \
    make \
    libgmp-dev \
    curl \
    libprotobuf-dev \
    protobuf-compiler \
    git \
    libtool \
    autoconf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone gRPC and install it
RUN git clone -b v1.41.1 --recursive https://github.com/grpc/grpc /grpc && \
    cd /grpc && \
    mkdir -p cmake/build && cd cmake/build && \
    cmake ../.. && \
    make && make install

# Install protobuf
RUN git clone https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
    git checkout v3.18.1 && \
    git submodule update --init --recursive && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Build and install Google Test
RUN mkdir -p /usr/src/gtest/build \
    && cd /usr/src/gtest/build \
    && cmake .. \
    && make \
    && cp lib/*.a /usr/lib

# Set working directory
WORKDIR /app

# Copy the CMake project
COPY . .

# Create the build directory and build the project using CMake
RUN mkdir -p build && cd build \
    && cmake .. \
    && make

# Specify command to run the application
CMD ["./build/grpc_client"]
# Use an official image with g++, cmake, and other build tools
FROM ubuntu:20.04

# Install necessary packages: build-essential, cmake, protobuf, gRPC, GTest, and dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    libgtest-dev \
    g++ \
    make \
    libgmp-dev \
    curl \
    libprotobuf-dev \
    protobuf-compiler \
    git \
    libtool \
    autoconf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone gRPC and install it
RUN git clone -b v1.41.1 --recursive https://github.com/grpc/grpc /grpc && \
    cd /grpc && \
    mkdir -p cmake/build && cd cmake/build && \
    cmake ../.. && \
    make && make install

# Install protobuf
RUN git clone https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
    git checkout v3.18.1 && \
    git submodule update --init --recursive && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Build and install Google Test
RUN mkdir -p /usr/src/gtest/build \
    && cd /usr/src/gtest/build \
    && cmake .. \
    && make \
    && cp lib/*.a /usr/lib

# Set working directory
WORKDIR /app

# Copy the CMake project
COPY . .

# Create the build directory and build the project using CMake
RUN mkdir -p build && cd build \
    && cmake .. \
    && make

# Specify command to run the application
CMD ["./build/grpc_client"]
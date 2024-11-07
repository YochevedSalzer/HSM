FROM ubuntu:20.04
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
    ca-certificates \  
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
# Clone gRPC and install it
RUN git config --global http.sslVerify false && \
    git clone -b v1.41.1 --recursive https://github.com/grpc/grpc /grpc && \
    cd /grpc && \
    mkdir -p cmake/build && cd cmake/build && \
    cmake ../.. && \
    make && make install
# התקן protobuf
RUN git clone https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
    git checkout v3.18.1 && \
    git submodule update --init --recursive && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig
# הגדר את תיקיית העבודה בתוך הקונטיינר
WORKDIR /app
# העתק את תוכן התיקייה הנוכחית לתוך הקונטיינר בכתובת /app
COPY . .
# צור תיקיית build
RUN rm -rf build && mkdir build
# שנה לתיקיית build
WORKDIR /app/build
# התקן את Google Test
RUN cd /usr/src/gtest && cmake CMakeLists.txt && make && \
    find /usr/src/gtest -name "*.a" -exec cp {} /usr/lib \;
# בנה את הפרויקט באמצעות CMake ו-Make
RUN cmake .. -DUSE_SYCL=OFF -DUSE_DEBUG=OFF
RUN make
WORKDIR /app
EXPOSE 50051
# פקודה להריץ את השרת (אופציונלי)
CMD ["./build/grpc_server"]
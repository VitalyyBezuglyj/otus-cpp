# Use an official Ubuntu image as the base
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Define build arguments for UID and GID
ARG UID=1000
ARG GID=1000

# Install necessary packages
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    git \
    clang \
    gdb \
    lldb \
    ninja-build \
    pkg-config \
    libssl-dev \
    curl \
    wget \
    vim \
    sudo \
    libboost-all-dev \
    libgtest-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*


RUN cd /usr/src/gtest && \
    cmake . && \
    make && \
    cp lib/*.a /usr/lib

# Create a group and user with the specified UID and GID
RUN groupadd -g $GID developer && \
    useradd -m -u $UID -g developer -s /bin/bash developer && \
    echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set the working directory
WORKDIR /usr/src/app

# Copy the local project files to the container
COPY . .

# Set permissions for the working directory
RUN chown -R developer:developer /usr/src/app

# Switch to the non-root user
USER developer

# Build the project using CMake
RUN cmake -Bbuild -S. -G Ninja && \
    cmake --build build

# Set the default command to run when the container starts
CMD ["/bin/bash"]

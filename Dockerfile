# Monero RandomX zkVM Verification - CPU Dockerfile
#
# Full RandomX with Argon2d (256 MiB cache) - CPU mode
# WARNING: CPU proving will take HOURS to DAYS. Use Dockerfile.gpu for GPU.
#
# Build: docker build -t randomx-zkvm .
# Run:   docker run randomx-zkvm

FROM rust:1.82-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    gcc \
    g++ \
    libssl-dev \
    pkg-config \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash zkvm
USER zkvm
WORKDIR /home/zkvm

# Install Risc0 toolchain
RUN curl -L https://risczero.com/install | bash
ENV PATH="/home/zkvm/.risc0/bin:${PATH}"
RUN /home/zkvm/.risc0/bin/rzup install

# Set up environment to use Risc0's Rust toolchain (1.91.1)
ENV PATH="/home/zkvm/.risc0/toolchains/v1.91.1-rust-x86_64-unknown-linux-gnu/bin:/home/zkvm/.risc0/bin:/home/zkvm/.cargo/bin:${PATH}"

# Copy project files
COPY --chown=zkvm:zkvm . /home/zkvm/project
WORKDIR /home/zkvm/project

# Build in release mode using Risc0's Rust
RUN cargo build --release

# Environment
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Create startup script
RUN echo '#!/bin/bash\n\
echo "============================================================"\n\
echo "  MONERO RANDOMX ZKVM - CPU MODE"\n\
echo "  WARNING: This will take HOURS to DAYS on CPU!"\n\
echo "  Use Dockerfile.gpu with CUDA for 50-100x faster proving."\n\
echo "============================================================"\n\
echo ""\n\
echo "Starting Full RandomX verification with Argon2d (256 MiB cache)..."\n\
echo "Logs will appear below."\n\
echo "============================================================"\n\
echo ""\n\
exec cargo run --release 2>&1 | tee /home/zkvm/project/benchmark.log\n\
' > /home/zkvm/project/start.sh && chmod +x /home/zkvm/project/start.sh

# Run automatically
CMD ["/bin/bash", "/home/zkvm/project/start.sh"]

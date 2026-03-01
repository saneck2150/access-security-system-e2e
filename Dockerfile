# Build stage
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++ \
    libsqlite3-dev \
    python3 \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build
RUN mkdir -p build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . -j$(nproc)

# Run tests
RUN cd build && ctest --output-on-failure

# Runtime stage
FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built binary
COPY --from=builder /app/build/access_admin/access_admin /app/access_admin

# Copy web UI
COPY --from=builder /app/web /app/web

# Copy default config
COPY --from=builder /app/config /app/config

# Create data directory for SQLite
RUN mkdir -p /app/data

# Expose HTTP port
EXPOSE 8080

# Default command
CMD ["/app/access_admin", "/app/config/access_security.yaml"]

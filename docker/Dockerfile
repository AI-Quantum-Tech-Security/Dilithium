
FROM ubuntu:latest
WORKDIR /app
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

RUN mkdir src
RUN echo "fn main() {}" > src/main.rs
RUN cargo build --release

COPY src ./src
RUN cargo build --release

FROM debian:buster-slim

WORKDIR /app

COPY --from=builder /app/target/release/Dilithium .

EXPOSE 3000

CMD ["./Dilithium"]
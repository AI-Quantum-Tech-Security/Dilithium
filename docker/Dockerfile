FROM rust:1.79-slim-bookworm as builder

RUN apt-get update && apt-get install -y openssl pkg-config

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y openssl

WORKDIR /app

COPY --from=builder /app/target/release/pqc-api .

EXPOSE 3000

CMD ["./pqc-api"]
# Dilithium

This service provides REST endpoints for signing and verifying messages using the post-quantum secure Dilithium-3 algorithm, standardized by NIST.

## Features

- Secure signature generation and verification
- `/sign` endpoint protected with internal API token
- `pqcrypto-dilithium` backed
- SBOM generation for CI/CD integrity

## Endpoints

### `POST /sign`

Sign a message.

**Headers**

**Body**
```json
{
  "message": "smth",
  "sk": "<base64 encoded secret key>"
}
{
  "signature": "<base64 signature>"
}
```

## Build & Run
```
cargo run
```

##Docker
```
docker build -t dilithium-signer .
docker run --env API_TOKEN=super-secret -p 8080:8080 dilithium-signer
```

## Next Steps

- Deploy to your k8s/dev env 
- Integrate with Spring Boot system via HTTP  
- Add Swagger (`utoipa`, optional)


This is where the actual cryptographic binary is built. You want to generate a CycloneDX SBOM (Software Bill of Materials) that captures:
Rust dependencies (e.g., pqcrypto-dilithium)
Compiler version
Crate versions and hashes
Build metadata

This proves:
You're not using unsafe crates
The code is deterministic and auditable
You're aligned with supply chain security standards like SLSA and NIST 800-218

Tool:
Use cyclonedx-rust-cargo in your GitHub Actions:

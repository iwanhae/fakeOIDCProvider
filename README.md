# Fake OIDC Provider

This project implements a fake OpenID Connect (OIDC) provider for development
and testing purposes. It simulates an OIDC server, allowing developers to test
OIDC authentication flows without setting up a full-fledged OIDC server.

## Features

- Configurable issuer and client ID
- In-memory storage of temporary user information
- RSA key generation for token signing
- Support for basic OIDC flows (Authorization Code flow)
- Customizable user information (name, email, groups)
- JWKS (JSON Web Key Set) endpoint for public key distribution

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/iwanhae/fakeoidcprovider.git
   cd fakeoidcprovider
   ```

2. Build the project:
   ```
   go build
   ```

## Usage

1. docker compose up -d
2. connect to http://localhost:8081 (example service that uses this fake OIDC
   provider)

## Endpoints

(http://localhost:8080)

- `/.well-known/openid-configuration`: OIDC discovery endpoint
- `/auth`: Authorization endpoint
- `/token`: Token endpoint
- `/userinfo`: UserInfo endpoint
- `/jwks`: JWKS endpoint

## License

Apache License 2.0

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

1. Start the fake OIDC provider:
   ```
   ./fakeoidcprovider
   ```

2. The server will start on the configured port (default: 8080)

3. Access the OIDC discovery endpoint:
   ```
   http://localhost:8080/.well-known/openid-configuration
   ```

4. To simulate user authentication, visit:
   ```
   http://localhost:8080/auth
   ```

## Endpoints

- `/.well-known/openid-configuration`: OIDC discovery endpoint
- `/auth`: Authorization endpoint
- `/token`: Token endpoint
- `/userinfo`: UserInfo endpoint
- `/jwks`: JWKS endpoint

## Development

This project uses Go modules for dependency management. To add or update
dependencies, use the standard Go module commands.

## Security Considerations

This fake OIDC provider is intended for development and testing purposes only.
It lacks many security features and should never be used in a production
environment.

## License

[Add your chosen license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

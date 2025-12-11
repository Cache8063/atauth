# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ATAuth, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please send an email describing the vulnerability to the maintainers. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fixes (optional)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

## Security Best Practices

When using ATAuth:

1. **Always use HTTPS** in production environments
2. **Keep HMAC secrets secure** - never commit them to version control
3. **Enable rate limiting** to prevent brute force attacks
4. **Verify tokens server-side** - client-side decoding is for display only
5. **Rotate secrets periodically** - especially if compromise is suspected
6. **Keep dependencies updated** - regularly update all packages

## Known Security Considerations

- Token verification uses constant-time comparison to prevent timing attacks
- Session tokens should be transmitted over secure channels only
- The gateway should be deployed behind a reverse proxy with TLS termination

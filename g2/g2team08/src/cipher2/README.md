# cipher2 Cipher Implementation

This directory implements the ChaCha20 stream cipher as specified in RFC 8439.

## Key Format
- First 32 bytes: ChaCha20 key
- Next 12 bytes: Nonce (random number)
- Last 4 bytes: Counter (little-endian u32)
- Total: 48 bytes, usually base64-encoded for external use

## Usage
- Build and run with `cargo run --bin cipher2` or `make`
- Supports encryption, decryption, and key generation commands
- Can be tested with the root project's `test.py` script

## Main Interfaces
- Implements `EncryptBytes` and `DecryptBytes` traits
- Command line arguments: see the main project README

## References
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc8439)
- [ChaCha20 Specification](https://tools.ietf.org/html/rfc8439#section-2.4)

## Implementation Details
- Uses 20 rounds (10 double rounds) as per RFC 8439
- Processes data in 64-byte blocks
- Symmetric cipher: encryption and decryption use the same algorithm 
# cipher1 Cipher Implementation

This directory implements a combined Hill cipher (8x8 matrix) and Caesar cipher.

## Key Format
- First 64 bytes: 8x8 invertible matrix, each element is 0~255
- Last 1 byte: Caesar cipher key (0~255)
- Total: 65 bytes, usually base64-encoded for external use

## Usage
- Build and run with `cargo run --bin cipher1` or `make`
- Supports encryption, decryption, and key generation commands

## Main Interfaces
- Implements `EncryptBytes` and `DecryptBytes` traits
- Command line arguments: see the main project README 
# AES-128 Encryption - Educational Implementation

This project was developed for educational purposes. It should not be used in production.

An implementation of the AES-128 (Advanced Encryption Standard) encryption algorithm in Rust, based on notes from lectures.

## This Project Demonstrates

1. **Key Expansion**: Deriving 11 round keys from the master key
2. **Block Cipher Operations**: SubBytes, ShiftRows, MixColumns, and AddRoundKey transformations
3. **Encryption & Decryption**: 10-round AES-128 cipher implementation
4. **Block Cipher Mode**: Handling messages longer than the 16-byte block size

## Getting Started

### Prerequisites

- Rust 1.70 or later (with Cargo)

### Installation

```bash
git clone https://github.com/erikhurinek/aes128_impl
cd aes128_impl
cargo build --release
```

### Running the Demo

```bash
cargo run
```

This will:
1. Generate a random 128-bit AES key
2. Read plaintext from `text/text00.txt`
3. Encrypt the message using AES-128
4. Decrypt it back to plaintext
5. Display both the ciphertext (hex) and decrypted message

## Project Structure

```
aes_test/
├── Cargo.toml              # Project dependencies
├── README.md               # This file
├── src/
│   ├── main.rs             # Demo application
│   ├── aes.rs              # AES-128 implementation
│   ├── lookup.rs           # S-box and RCON lookup tables
│   └── util.rs             # State management and transformations
└── text/
    ├── text00.txt          # Sample plaintext (short)
    └── text01.txt          # Sample plaintext (long)
```

## Dependencies

```toml
hex = "0.4.3"       # Hex encoding for display
rand = "0.10.1"     # Random number generation for key generation
```

## Key Implementation Details

- **Algorithm**: AES-128 (128-bit key, 128-bit block size, 10 rounds)
- **S-Box**: Standard AES SubBytes lookup table
- **State Representation**: 4x4 column-major byte matrix
- **Key Schedule**: Rijndael Key Expansion algorithm
- **Transformations**: SubBytes, ShiftRows, MixColumns, AddRoundKey

## Limitations & Notes

- This is a pure software implementation without hardware acceleration
- Uses 128-bit keys only (no support for 192-bit or 256-bit keys)
- Implements ECB mode for simplicity (not recommended for secure encryption)
- For production use, consider using the [aes crate](https://docs.rs/aes/latest/aes/) with hardware acceleration


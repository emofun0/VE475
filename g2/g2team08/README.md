# g2team08

ece475

Yipeng Wang 521370910078

## Quick Start

```bash
cargo run --bin cipher1
```
or
```bash
cd src/cipher1
make
./g2
```
to use cipher1. To use cipher2, just change '1' to '2'.

### supported commands:
* `--generate`: generate a random key, not the default key
* `--encrypt []`: encrypt given message, using default key
* `--decrypt []`: decrypt given ciphertext, using default key
* `--key []`: use chosen key when encrypting and decrypting

### Note:
If your input is not proper, you may see some errors. Sorry for that
because I did not add checks to all errors. Errors means your input is
not correct!

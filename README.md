# bip39

A from-scratch Rust implementation of [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
mnemonic codes, written step by step for learning.

> **Not audited. Do not use it to protect real funds.**
> Generate wallets for real money with a hardware wallet or a well-reviewed library.

## How BIP-39 works

```
entropy (128–256 bits)
   │  SHA-256, take the first ENT/32 bits
   ▼
entropy ‖ checksum            132 … 264 bits
   │  split into 11-bit groups, each is an index 0..2047
   ▼
12 … 24 words from the wordlist
   │  PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" + passphrase
   ▼
64-byte seed
```

| Entropy | Checksum | Words |
|--------:|---------:|------:|
| 128 bit | 4 bit    | 12    |
| 160 bit | 5 bit    | 15    |
| 192 bit | 6 bit    | 18    |
| 224 bit | 7 bit    | 21    |
| 256 bit | 8 bit    | 24    |

## Command-line tool

```sh
cargo build --release
alias bip39=./target/release/bip39

bip39 generate            # 12 words; also 15, 18, 21, 24
bip39 validate "<phrase>" # checks the words and the checksum
bip39 entropy  "<phrase>" # prints the entropy as hex
bip39 seed     "<phrase>" # prints the 64-byte seed as hex
```

`seed` never takes the passphrase as an argument, because arguments leak into
shell history and `ps`. On a terminal you are prompted without echo and asked to
confirm (a typo silently gives a different wallet). When stdin is piped, one line
is read instead; an empty line means no passphrase:

```sh
echo TREZOR | bip39 seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Exit status is non-zero and the message goes to stderr on invalid input.

## Library

```rust
use bip39::{entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic};

let phrase = entropy_to_mnemonic(&[0x7f; 16]).unwrap().join(" ");
assert_eq!(
    phrase,
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
);

assert!(validate_mnemonic(&phrase).is_ok());
assert_eq!(&mnemonic_to_entropy(&phrase).unwrap()[..], &[0x7f; 16]);

let seed = mnemonic_to_seed(&phrase, "my passphrase"); // 64 bytes, zeroed on drop
```

| Function | Purpose |
|---|---|
| `generate_entropy(n)` / `generate_entropy_with(src, n)` | random bytes from the OS or a custom `EntropySource` |
| `checksum(entropy)` | first `ENT/32` bits of `SHA-256(entropy)` |
| `entropy_to_mnemonic(entropy)` / `generate_mnemonic(n)` | entropy to words |
| `mnemonic_to_entropy(phrase)` / `validate_mnemonic(phrase)` | words back to entropy, with checksum verification |
| `mnemonic_to_seed(phrase, passphrase)` | PBKDF2 seed; the phrase is **not** validated, as the spec does not require it |

Secrets (`entropy`, `seed`) are returned in `Zeroizing` buffers that are wiped on drop.

### Entropy source

Randomness comes from the operating system's CSPRNG through
[`getrandom`](https://crates.io/crates/getrandom) (`getentropy` on macOS,
`getrandom(2)` on Linux, `ProcessPrng` on Windows). Implement `EntropySource`
to plug in anything else, for example a deterministic source in tests.

For `wasm32-unknown-unknown` (browser, Node) enable the `wasm-js` feature:

```sh
cargo build --target wasm32-unknown-unknown --features wasm-js
```

It is opt-in because the upstream crate advises against enabling it unconditionally in libraries.

## Layout

```
src/entropy.rs    EntropySource, OsEntropy, generate_entropy*
src/mnemonic.rs   wordlist, entropy <-> mnemonic, validation
src/seed.rs       mnemonic -> seed (PBKDF2-HMAC-SHA512, NFKD)
src/main.rs       command-line tool
src/wordlists/    english.txt from bitcoin/bips
tests/            official Trezor vectors
```

## Testing

```sh
cargo test
```

Unit tests, doctests, and all 24 English vectors from
[trezor/python-mnemonic](https://github.com/trezor/python-mnemonic/blob/master/vectors.json)
(`tests/vectors.json`) checked in both directions, plus seed derivation with the
`TREZOR` passphrase. Seeds for Unicode passphrases were cross-checked against
Python's `hashlib`.

## Not implemented

- Wordlists other than English (the Japanese list also needs the ideographic space `U+3000`).
- BIP-32 key derivation from the seed.

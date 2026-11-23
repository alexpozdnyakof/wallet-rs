use zeroize::Zeroizing;

use crate::Error;

/// Allowed entropy sizes in bytes: 128, 160, 192, 224, 256 bits.
pub(crate) const VALID_ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

pub(crate) fn check_len(bytes: usize) -> Result<(), Error> {
    if VALID_ENTROPY_BYTES.contains(&bytes) {
        Ok(())
    } else {
        Err(Error::InvalidEntropyLength(bytes))
    }
}

/// A source of random bytes.
///
/// Implement it to replace the OS in tests or to add other sources
/// (dice rolls, a hardware TRNG).
pub trait EntropySource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// The operating system's CSPRNG, accessed through `getrandom`.
///
/// Works on every platform `getrandom` supports; on `wasm32-unknown-unknown`
/// enable the `wasm-js` feature.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

/// Fills a buffer of `bytes` bytes from `src`; the buffer is zeroed on drop.
///
/// `bytes` must be one of 16, 20, 24, 28, 32.
///
/// ```
/// use bip39::{EntropySource, Error, generate_entropy_with};
///
/// struct Fixed;
/// impl EntropySource for Fixed {
///     fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
///         buf.fill(7);
///         Ok(())
///     }
/// }
///
/// assert_eq!(&generate_entropy_with(&mut Fixed, 16).unwrap()[..], &[7u8; 16]);
/// ```
pub fn generate_entropy_with(
    src: &mut impl EntropySource,
    bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_len(bytes)?;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    src.fill(&mut buf)?;
    Ok(buf)
}

/// Generates `bytes` bytes of entropy from the OS CSPRNG.
///
/// `bytes` must be one of 16, 20, 24, 28, 32 (128 to 256 bits).
pub fn generate_entropy(bytes: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    generate_entropy_with(&mut OsEntropy, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);
    impl EntropySource for Fixed {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            buf.fill(self.0);
            Ok(())
        }
    }

    struct Broken;
    impl EntropySource for Broken {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Rng)
        }
    }

    #[test]
    fn length_checked() {
        assert_eq!(generate_entropy(15), Err(Error::InvalidEntropyLength(15)));
        assert_eq!(generate_entropy(16).unwrap().len(), 16);
        assert_eq!(generate_entropy(32).unwrap().len(), 32);
    }

    #[test]
    fn custom_source_is_used() {
        let e = generate_entropy_with(&mut Fixed(0x7f), 16).unwrap();
        assert_eq!(&e[..], &[0x7f; 16]);
    }

    #[test]
    fn source_error_propagates() {
        assert_eq!(generate_entropy_with(&mut Broken, 16), Err(Error::Rng));
    }

    #[test]
    fn os_calls_differ() {
        let a = generate_entropy(32).unwrap();
        let b = generate_entropy(32).unwrap();
        assert_ne!(&a[..], &b[..]);
    }
}

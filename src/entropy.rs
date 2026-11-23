use zeroize::Zeroizing;

use crate::Error;

/// Допустимые размеры энтропии в байтах: 128, 160, 192, 224, 256 бит.
pub(crate) const VALID_ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

pub(crate) fn check_len(bytes: usize) -> Result<(), Error> {
    if VALID_ENTROPY_BYTES.contains(&bytes) {
        Ok(())
    } else {
        Err(Error::InvalidEntropyLength(bytes))
    }
}

/// Источник случайных байт. Позволяет подменять ОС в тестах
/// и добавлять другие источники (кости, аппаратный TRNG).
pub trait EntropySource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// CSPRNG операционной системы (через `getrandom`, работает на всех её платформах).
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

/// Энтропия из заданного источника. Буфер затирается при drop.
pub fn generate_entropy_with(
    src: &mut impl EntropySource,
    bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_len(bytes)?;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    src.fill(&mut buf)?;
    Ok(buf)
}

/// Энтропия из ОС.
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

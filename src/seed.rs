use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

const ROUNDS: u32 = 2048;
/// Length of the seed in bytes.
pub const SEED_LEN: usize = 64;

/// Derives the 64-byte seed from a mnemonic and an optional passphrase.
///
/// Uses PBKDF2-HMAC-SHA512 with 2048 iterations and the salt
/// `"mnemonic" + passphrase`. Both inputs are normalized to NFKD first, as
/// the specification requires. Pass `""` for no passphrase.
///
/// The phrase is not validated, as the specification does not require it;
/// call [`validate_mnemonic`](crate::validate_mnemonic) first.
///
/// ```
/// let seed = bip39::mnemonic_to_seed("abandon abandon abandon abandon abandon abandon \
///     abandon abandon abandon abandon abandon about", "TREZOR");
/// assert_eq!(seed[..4], [0xc5, 0x52, 0x57, 0xc3]);
/// ```
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Zeroizing<[u8; SEED_LEN]> {
    let password: Zeroizing<String> = Zeroizing::new(mnemonic.nfkd().collect());
    let mut salt = Zeroizing::new(String::from("mnemonic"));
    salt.extend(passphrase.nfkd());

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), ROUNDS, &mut *seed);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const ABOUT: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Official Trezor vector; the value was recomputed independently with Python hashlib.
    #[test]
    fn vector_trezor_passphrase() {
        assert_eq!(
            hex(&*mnemonic_to_seed(ABOUT, "TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn empty_passphrase() {
        assert_eq!(
            hex(&*mnemonic_to_seed(ABOUT, "")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn unicode_passphrase_matches_reference() {
        assert_eq!(
            hex(&*mnemonic_to_seed(ABOUT, "пароль ё\u{e9}")),
            "c3ddf639442aba841af12bbcd21c34aa762e2b492d89571ab76415c0ae345bd6039e65a7c1e7a39b5b22b817a561412e21a52c336182c3ccc82a4ad8f2163ec0"
        );
    }

    #[test]
    fn nfkd_makes_composed_and_decomposed_equal() {
        // "é" as one code point vs "e" + combining acute accent
        assert_eq!(
            *mnemonic_to_seed(ABOUT, "caf\u{e9}"),
            *mnemonic_to_seed(ABOUT, "cafe\u{301}")
        );
    }

    #[test]
    fn passphrase_changes_seed() {
        assert_ne!(*mnemonic_to_seed(ABOUT, "a"), *mnemonic_to_seed(ABOUT, "b"));
    }
}

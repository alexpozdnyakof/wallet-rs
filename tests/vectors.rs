//! Официальные векторы trezor/python-mnemonic (английский словарь, passphrase "TREZOR").

use bip39::{entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_english_vectors() {
    let data: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let vectors = data["english"].as_array().unwrap();
    assert_eq!(vectors.len(), 24);

    for (n, v) in vectors.iter().enumerate() {
        let [entropy_hex, phrase, seed_hex] = [0, 1, 2].map(|i| v[i].as_str().unwrap());
        let entropy = unhex(entropy_hex);

        assert_eq!(
            entropy_to_mnemonic(&entropy).unwrap().join(" "),
            phrase,
            "entropy -> mnemonic, vector #{n}"
        );
        assert_eq!(
            hex(&mnemonic_to_entropy(phrase).unwrap()),
            entropy_hex,
            "mnemonic -> entropy, vector #{n}"
        );
        assert_eq!(validate_mnemonic(phrase), Ok(()), "validate, vector #{n}");
        assert_eq!(
            hex(&*mnemonic_to_seed(phrase, "TREZOR")),
            seed_hex,
            "seed, vector #{n}"
        );
    }
}

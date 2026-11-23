use std::process::ExitCode;

use bip39::{generate_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic};

const USAGE: &str = "\
usage:
  bip39 generate [12|15|18|21|24]     new mnemonic (default 12 words)
  bip39 validate \"<phrase>\"           check words and checksum
  bip39 entropy  \"<phrase>\"           print entropy as hex
  bip39 seed     \"<phrase>\" [pass]    print 64-byte seed as hex";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(args: &[String]) -> Result<String, String> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("generate") => {
            let words: usize = arg(1).unwrap_or("12").parse().map_err(|_| "word count must be a number")?;
            // ENT = words * 11 * 32 / 33 бит -> байты
            if !matches!(words, 12 | 15 | 18 | 21 | 24) {
                return Err("word count must be one of 12, 15, 18, 21, 24".into());
            }
            let m = generate_mnemonic(words * 11 * 32 / 33 / 8).map_err(|e| format!("{e:?}"))?;
            Ok(m.join(" "))
        }
        Some("validate") => {
            validate_mnemonic(arg(1).ok_or(USAGE)?).map_err(|e| format!("invalid: {e:?}"))?;
            Ok("valid".into())
        }
        Some("entropy") => {
            let e = mnemonic_to_entropy(arg(1).ok_or(USAGE)?).map_err(|e| format!("invalid: {e:?}"))?;
            Ok(hex(&e))
        }
        Some("seed") => {
            let phrase = arg(1).ok_or(USAGE)?;
            validate_mnemonic(phrase).map_err(|e| format!("invalid: {e:?}"))?;
            Ok(hex(&*mnemonic_to_seed(phrase, arg(2).unwrap_or(""))))
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

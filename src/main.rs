use std::io::{IsTerminal, stdin};
use std::process::ExitCode;

use zeroize::Zeroizing;

use bip39::{generate_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic};

const USAGE: &str = "\
usage:
  bip39 generate [12|15|18|21|24]     new mnemonic (default 12 words)
  bip39 validate \"<phrase>\"           check words and checksum
  bip39 entropy  \"<phrase>\"           print entropy as hex
  bip39 seed     \"<phrase>\"           print 64-byte seed as hex

The passphrase for `seed` is never taken from arguments (they leak into
shell history and `ps`). On a terminal you are prompted without echo and
asked to confirm; otherwise one line is read from stdin (empty = none).";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read_passphrase() -> Result<Zeroizing<String>, String> {
    let err = |e: std::io::Error| format!("cannot read passphrase: {e}");
    if stdin().is_terminal() {
        let first = Zeroizing::new(rpassword::prompt_password("Passphrase (empty for none): ").map_err(err)?);
        let again = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ").map_err(err)?);
        // опечатка в passphrase тихо даст другой кошелёк, поэтому спрашиваем дважды
        if first != again {
            return Err("passphrases do not match".into());
        }
        Ok(first)
    } else {
        let mut line = Zeroizing::new(String::new());
        stdin().read_line(&mut line).map_err(err)?;
        Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned()))
    }
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
            if arg(2).is_some() {
                return Err("passphrase is no longer accepted as an argument; \
                            enter it at the prompt or pipe it via stdin"
                    .into());
            }
            validate_mnemonic(phrase).map_err(|e| format!("invalid: {e:?}"))?;
            let passphrase = read_passphrase()?;
            Ok(hex(&*mnemonic_to_seed(phrase, &passphrase)))
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

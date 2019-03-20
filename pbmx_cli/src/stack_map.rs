use crate::Config;
use pbmx_kit::{
    crypto::{
        map,
        vtmf::{Stack, Vtmf},
    },
    state::{PrivateSecretMap, SecretMap},
};
use std::fmt::{self, Display, Formatter};

struct DisplayStackContents<'a>(
    &'a Stack,
    &'a SecretMap,
    &'a PrivateSecretMap,
    &'a Vtmf,
    &'a Config,
);
pub fn display_stack_contents<'a>(
    stack: &'a Stack,
    secrets: &'a SecretMap,
    private_secrets: &'a PrivateSecretMap,
    vtmf: &'a Vtmf,
    config: &'a Config,
) -> impl Display + 'a {
    DisplayStackContents(stack, secrets, private_secrets, vtmf, config)
}

impl<'a> Display for DisplayStackContents<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        let mut count_encrypted = 0;
        write!(f, "[")?;
        let my_fp = &self.3.private_key().fingerprint();
        for m in self.0.iter() {
            let mut m = *m;
            while let Some(d) = self.2.get(&m) {
                m -= d;
            }
            if let Some((d, fp)) = self.1.get(&m) {
                m = self.3.unmask(&m, d);
                if !fp.contains(my_fp) {
                    m = self.3.unmask_private(&m);
                }
            }
            let u = self.3.unmask_open(&m);
            if let Some(token) = map::from_curve(&u) {
                if count_encrypted > 0 {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "?{}", count_encrypted)?;
                    first = false;
                    count_encrypted = 0;
                }
                if self.4.tokens.is_empty() {
                    if let Some(last) = last_in_seq {
                        if last + 1 == token {
                            unfinished_seq = true;
                        } else {
                            if unfinished_seq {
                                write!(f, "-{}", last)?;
                                unfinished_seq = false;
                            }
                            write!(f, " {}", token)?;
                        }
                    } else {
                        if !first {
                            write!(f, " ")?;
                        }
                        write!(f, "{}", token)?;
                    }
                } else {
                    if !first {
                        write!(f, " ")?;
                    }
                    let s = self.4.tokens.get(&token);
                    if let Some(s) = s {
                        write!(f, "{}", s)?;
                    } else {
                        write!(f, "{}", token)?;
                    }
                }
                last_in_seq = Some(token);
                first = false;
            } else {
                last_in_seq = None;
                count_encrypted += 1;
            }
        }
        if count_encrypted > 0 {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "?{}", count_encrypted)?;
        }
        if unfinished_seq {
            let last = last_in_seq.unwrap();
            write!(f, "-{}", last)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

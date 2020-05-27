use crate::Config;
use pbmx_kit::{
    crypto::{
        keys::Fingerprint,
        map,
        vtmf::{Mask, Stack, Vtmf},
    },
    state::{PrivateSecretMap, SecretMap},
};
use std::fmt::{self, Display, Formatter};

struct DisplayStackContents<'a> {
    stack: &'a Stack,
    secrets: &'a SecretMap,
    private_secrets: &'a PrivateSecretMap,
    vtmf: &'a Vtmf,
    config: &'a Config,
}
pub fn display_stack_contents<'a>(
    stack: &'a Stack,
    secrets: &'a SecretMap,
    private_secrets: &'a PrivateSecretMap,
    vtmf: &'a Vtmf,
    config: &'a Config,
) -> impl Display + 'a {
    DisplayStackContents {
        stack,
        secrets,
        private_secrets,
        vtmf,
        config,
    }
}

fn unmask_with_public_secrets(
    mut m: Mask,
    secrets: &SecretMap,
    vtmf: &Vtmf,
    my_fp: &Fingerprint,
) -> Option<Mask> {
    if let Some((d, fp)) = secrets.get(&m) {
        m = vtmf.unmask(&m, d);
        if !fp.contains(my_fp) {
            m = vtmf.unmask_private(&m);
            if fp.len() + 1 == vtmf.parties() {
                return Some(m);
            }
        } else {
            if fp.len() == vtmf.parties() {
                return Some(m);
            }
        }
    } else {
        if m.is_open() {
            return Some(m);
        }
    }
    None
}

fn unmask_with_private_secrets(
    mut m: Mask,
    secrets: &SecretMap,
    private_secrets: &PrivateSecretMap,
    vtmf: &Vtmf,
    my_fp: &Fingerprint,
) -> Option<Mask> {
    while let Some(d) = private_secrets.get(&m) {
        m -= d;
        if m.is_open() {
            return Some(m);
        }
        let unmasked = unmask_with_public_secrets(m, secrets, vtmf, my_fp);
        if unmasked.is_some() {
            return unmasked;
        }
    }
    None
}

impl<'a> Display for DisplayStackContents<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut first = true;
        let mut last_in_seq = None;
        let mut unfinished_seq = false;
        let mut count_encrypted = 0;
        write!(f, "[")?;
        let my_fp = &self.vtmf.private_key().fingerprint();
        for m in self.stack.iter() {
            let m =
                unmask_with_public_secrets(*m, &self.secrets, &self.vtmf, &my_fp).or_else(|| {
                    unmask_with_private_secrets(
                        *m,
                        &self.secrets,
                        &self.private_secrets,
                        &self.vtmf,
                        &my_fp,
                    )
                });
            if let Some(m) = m {
                let u = self.vtmf.unmask_open(&m);
                let token = map::from_curve(&u);
                if count_encrypted > 0 {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "?{}", count_encrypted)?;
                    first = false;
                    count_encrypted = 0;
                }
                if self.config.tokens.is_empty() {
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
                    let s = self.config.tokens.get(&token);
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

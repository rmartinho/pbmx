use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use digest::XofReader;
use pbmx_curve::{
    keys::Fingerprint,
    vtmf::{Mask, SecretShare, Vtmf},
};
use std::iter;

#[derive(Debug)]
pub struct Rng {
    bound: u64,
    entropy: Mask,
    entropy_fp: Vec<Fingerprint>,
    secret: SecretShare,
    secret_fp: Vec<Fingerprint>,
}

impl Rng {
    pub fn new(bound: u64) -> Self {
        Self {
            bound,
            entropy: Mask::open(RistrettoPoint::identity()),
            entropy_fp: Vec::new(),
            secret: RistrettoPoint::identity(),
            secret_fp: Vec::new(),
        }
    }

    pub fn bound(&self) -> u64 {
        self.bound
    }

    pub fn mask(&self) -> &Mask {
        &self.entropy
    }

    pub fn add_entropy(&mut self, party: Fingerprint, share: &Mask) {
        self.entropy += share;
        self.entropy_fp.push(party);
    }

    pub fn add_secret(&mut self, party: Fingerprint, share: &SecretShare) {
        self.secret += share;
        self.secret_fp.push(party);
    }

    pub fn entropy_parties(&self) -> &[Fingerprint] {
        &self.entropy_fp
    }

    pub fn secret_parties(&self) -> &[Fingerprint] {
        &self.secret_fp
    }

    pub fn is_complete(&self, vtmf: &Vtmf) -> bool {
        self.entropy_parties().len() == vtmf.parties() as usize
            && self.secret_parties().len() == vtmf.parties() as usize
    }

    pub fn gen(&self, vtmf: &Vtmf) -> u64 {
        let max = iter::repeat(self.bound)
            .scan(1u64, |s, x| {
                let (r, overflow) = s.overflowing_mul(x);
                if overflow {
                    None
                } else {
                    *s = r;
                    Some(*s)
                }
            })
            .last()
            .unwrap();

        let r = vtmf.unmask(&self.entropy, &self.secret);
        let mut reader = vtmf.unmask_random(&r);
        loop {
            let mut buf = [0u8; 8];
            reader.read(&mut buf);
            let x = u64::from_be_bytes(buf);
            if x < max {
                return x % self.bound;
            }
        }
    }
}

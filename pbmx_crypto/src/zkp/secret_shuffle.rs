//! Groth's verifiable secret shuffle of homomorphic encryptions

use crate::{
    barnett_smart::Mask,
    hash::{hash_iter, Hash},
    num::{fpowm, Bits, Modulo},
    pedersen::CommitmentScheme,
    perm::Permutation,
    schnorr,
    zkp::known_shuffle,
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};

/// Non-interactive proof result
#[derive(Debug)]
pub struct Proof {
    com: CommitmentScheme,
    skc: known_shuffle::Proof,
    c: Integer,
    cd: Integer,
    ed: (Integer, Integer),
    fi: Vec<Integer>,
    z: Integer,
}

/// Generates a non-interactive zero-knowledge proof of a secret shuffle
pub fn prove(
    group: &schnorr::Group,
    h: &Integer,
    e: &[Mask],
    pi: &Permutation,
    ri: &[Integer],
) -> Proof {
    assert!(e.len() == ri.len());

    let g = group.generator();
    let p = group.modulus();
    let q = group.order();
    let n = e.len();
    let com = CommitmentScheme::new(group.clone(), h.clone(), n).unwrap();

    let mut rng = thread_rng();

    let d: Vec<_> = rng
        .sample_iter(&Bits(2 * Hash::output_size() as u32))
        .map(|d| -d)
        .take(n)
        .collect();

    let p2: Vec<_> = pi.iter().map(|p| Integer::from(p + 1)).collect();
    let (c, r) = com.commit_to(&p2);
    let (cd, rd) = com.commit_to(&d);

    let re = rng.sample(&Modulo(q));
    let c1 = fpowm::pow_mod(g, &re, p).unwrap();
    let c2 = fpowm::pow_mod(h, &re, p).unwrap();

    let ed = d
        .iter()
        .zip(e.iter())
        .map(|(d, (e1, e2))| {
            let x1 = fpowm::pow_mod(e1, d, p).unwrap() * &c1 % p;
            let x2 = fpowm::pow_mod(e2, d, p).unwrap() * &c2 % p;
            (x1, x2)
        })
        .fold(
            (Integer::from(1), Integer::from(1)),
            |(a1, a2), (e1, e2)| (a1 * e1, a2 * e2),
        );

    let ti = t_challenge(&c, &cd, &ed, e);
    let fi: Vec<_> = pi
        .iter()
        .zip(d.iter())
        .map(|(p, d)| Integer::from(&ti[*p] - d))
        .collect();
    let z = pi
        .iter()
        .zip(ri.iter())
        .map(|(p, r)| Integer::from(&ti[*p] * r))
        .sum::<Integer>()
        + &rd;

    let l = l_challenge(&fi, &z, &ti);
    let rho = (&l * r % q + rd) % q;

    let m: Vec<_> = (0..n)
        .map(|i| (&l * Integer::from(i + 1) % q + &ti[i]) % q)
        .collect();

    let skc = known_shuffle::prove(&com, &l, &m, &pi, &rho);

    Proof {
        com,
        skc,
        c,
        cd,
        ed,
        fi,
        z,
    }
}

/// Verifies a non-interactive zero-knowledge proof of a secret shuffle
pub fn verify(_group: &schnorr::Group, _h: &Integer, _e: &[Mask], _proof: &Proof) -> bool {
    unimplemented!()
}

fn t_challenge(c: &Integer, cd: &Integer, ed: &(Integer, Integer), e: &[Mask]) -> Vec<Integer> {
    let mut hash = Hash::new();
    hash = hash
        .chain(&c.to_digits(Order::MsfBe))
        .chain(&cd.to_digits(Order::MsfBe))
        .chain(&ed.0.to_digits(Order::MsfBe))
        .chain(&ed.1.to_digits(Order::MsfBe));
    for e in e {
        hash = hash
            .chain(&e.0.to_digits(Order::MsfBe))
            .chain(&e.1.to_digits(Order::MsfBe));
    }
    hash_iter(hash)
        .map(|r| Integer::from_digits(&r, Order::MsfBe))
        .take(e.len())
        .collect()
}

fn l_challenge(f: &[Integer], z: &Integer, t: &[Integer]) -> Integer {
    let mut hash = Hash::new();
    for f in f {
        hash = hash.chain(&f.to_digits(Order::MsfBe));
    }
    hash = hash.chain(&z.to_digits(Order::MsfBe));
    for t in t {
        hash = hash.chain(&t.to_digits(Order::MsfBe));
    }
    Integer::from_digits(&hash.result(), Order::MsfBe)
}

#[cfg(test)]
mod test {}

//! Groth's verifiable shuffle of known content

use crate::{
    commit::CommitmentScheme,
    hash::Hash,
    num::{fpowm, Modulo},
    perm::Permutation,
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Non-interactive proof result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    cd: Integer,
    cdd: Integer,
    cda: Integer,
    f: Vec<Integer>,
    z: Integer,
    fd: Vec<Integer>,
    zd: Integer,
}

/// Generates a non-interactive zero-knowledge proof of a shuffle of known
/// content
pub fn prove(
    com: &CommitmentScheme,
    l: &Integer,
    m: &[Integer],
    pi: &Permutation,
    r: &Integer,
) -> Proof {
    let q = com.group().order();
    let n = m.len();
    let mut rng = thread_rng();

    let x = x_challenge(m, l);

    let d: Vec<_> = rng.sample_iter(&Modulo(q)).take(n).collect();

    let mut delta = Vec::with_capacity(n);
    delta.push(d[0].clone());
    delta.extend(rng.sample_iter(&Modulo(q)).take(n - 2));
    delta.push(Integer::new());

    let a: Vec<_> = (1..=n)
        .map(|i| {
            pi.iter()
                .take(i)
                .map(|&p| Integer::from(&m[p] - &x) % q)
                .fold(Integer::from(1), |acc, v| acc * v % q)
        })
        .collect();

    let (cd, rd) = com.commit_to(&d);
    let mut dd: Vec<_> = (1..n)
        .map(|i| Integer::from(-&delta[i - 1]) * &d[i] % q)
        .collect();
    dd.push(Integer::new());
    let (cdd, rdd) = com.commit_to(&dd);
    let mut da: Vec<_> = (1..n)
        .map(|i| {
            ((&delta[i] - Integer::from(&m[pi[i]] - &x) % q * &delta[i - 1] % q) % q
                - Integer::from(&a[i - 1] * &d[i]) % q)
                % q
        })
        .collect();
    da.push(Integer::new());
    let (cda, rda) = com.commit_to(&da);

    let e = e_challenge(&cd, &cdd, &cda, &x);

    let f: Vec<_> = pi
        .iter()
        .zip(d.iter())
        .map(|(&p, d)| (Integer::from(&e * &m[p]) % q + d) % q)
        .collect();
    let z = (&e * r + rd) % q;

    let mut fd: Vec<_> = (1..n)
        .map(|i| {
            (&e * (&delta[i]
                - Integer::from(&m[pi[i]] - &x) * &delta[i - 1] % q
                - Integer::from(&a[i - 1] * &d[i]))
                % q
                - Integer::from(&delta[i - 1] * &d[i]))
                % q
        })
        .collect();
    fd.push(Integer::new());
    let zd = (&e * rda + rdd) % q;

    Proof {
        cd,
        cdd,
        cda,
        f,
        z,
        fd,
        zd,
    }
}

/// Verifies a non-interactive zero-knowledge proof of a shuffle of known
/// content
pub fn verify(
    com: &CommitmentScheme,
    l: &Integer,
    c: &Integer,
    m: &[Integer],
    proof: &Proof,
) -> bool {
    let q = com.group().order();
    let p = com.group().modulus();
    let n = m.len();

    if !com.group().has_element(&proof.cd) {
        return false;
    }
    if !com.group().has_element(&proof.cdd) {
        return false;
    }
    if !com.group().has_element(&proof.cda) {
        return false;
    }
    if proof.f.iter().any(|f| f.cmp_abs(q) != Ordering::Less) {
        return false;
    }
    if proof.z.cmp_abs(q) != Ordering::Less {
        return false;
    }
    if proof.fd.iter().any(|f| f.cmp_abs(q) != Ordering::Less) {
        return false;
    }
    if proof.zd.cmp_abs(q) != Ordering::Less {
        return false;
    }

    let x = x_challenge(m, l);
    let e = e_challenge(&proof.cd, &proof.cdd, &proof.cda, &x);

    let cecd = fpowm::pow_mod(&c, &e, p).unwrap() * &proof.cd % p;
    if !com.open(&cecd, &proof.f, &proof.z) {
        return false;
    }
    let ceca = fpowm::pow_mod(&proof.cda, &e, p).unwrap() * &proof.cdd % p;
    if !com.open(&ceca, &proof.fd, &proof.zd) {
        return false;
    }

    let e1 = Integer::from(e.invert_ref(q).unwrap());
    let ex = Integer::from(&e * &x);
    let mut ff = Integer::from(&proof.f[0] - &ex) % q;
    for i in 1..n {
        ff = (ff * Integer::from(&proof.f[i] - &ex) % q + &proof.fd[i - 1]) % q;
        ff = ff * &e1 % q;
        ff = (ff + q) % q;
    }
    let prod = m
        .iter()
        .map(|m| Integer::from(m - &x) % q)
        .fold(Integer::from(1), |acc, i| acc * i % q);
    ff == (e * prod % q + q) % q
}

fn x_challenge(m: &[Integer], l: &Integer) -> Integer {
    let mut hash = Hash::new();
    for m in m {
        hash = hash.chain(&m.to_digits(Order::MsfBe));
    }
    hash = hash.chain(&l.to_digits(Order::MsfBe));
    Integer::from_digits(&hash.result(), Order::MsfBe)
}

fn e_challenge(cd: &Integer, cdd: &Integer, cda: &Integer, x: &Integer) -> Integer {
    let mut hash = Hash::new();
    hash = hash
        .chain(&cd.to_digits(Order::MsfBe))
        .chain(&cdd.to_digits(Order::MsfBe))
        .chain(&cda.to_digits(Order::MsfBe))
        .chain(&x.to_digits(Order::MsfBe));
    Integer::from_digits(&hash.result(), Order::MsfBe)
}

#[cfg(test)]
mod test {
    use super::{prove, verify};
    use crate::{commit::CommitmentScheme, group::Groups, num::Bits, perm::Shuffles};
    use rand::{thread_rng, Rng};
    use rug::Integer;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();
        let dist = Groups {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let h = group.element(&rng.sample(&Bits(128)));

        let m: Vec<_> = (0..8).map(Integer::from).collect();
        let mut mp = m.clone();
        let pi = rng.sample(&Shuffles(8));
        pi.apply_to(&mut mp);

        let com = CommitmentScheme::new(group, h, 8).unwrap();
        let l = rng.sample(&Bits(160));
        let (c, r) = com.commit_to(&mp);
        let mut proof = prove(&com, &l, &m, &pi, &r);

        let ok = verify(&com, &l, &c, &m, &proof);
        assert!(
            ok,
            "proof isn't valid\n\tcom = {:#?}\n\tc = {}\n\tm = {:?}\n\tp = {:#?}\n\tr = {}\n\tproof = {:?}",
            com,
            c,
            m,
            pi,
            r,
            proof
        );

        // break the proof
        proof.z += 1;
        let ok = verify(&com, &l, &c, &m, &proof);
        assert!(
            !ok,
            "invalid proof was accepted\n\tcom = {:#?}\n\tc = {}\n\tm = {:?}\n\tp = {:#?}\n\tr = {}\n\tproof = {:?}",
            com,
            c,
            m,
            pi,
            r,
            proof
        );
    }
}

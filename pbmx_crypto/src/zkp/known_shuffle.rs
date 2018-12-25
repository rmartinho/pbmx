//! Groth's verifiable shuffle of known content

use crate::{
    barnett_smart::Mask,
    hash::{hash_iter, Hash},
    num::{fpowm, Bits, Modulo},
    pedersen::CommitmentScheme,
    perm::Permutation,
    schnorr,
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};

/// Non-interactive proof result
#[derive(Debug)]
pub struct Proof {
    cd: Integer,
    cdd: Integer,
    cda: Integer,
    f: Vec<Integer>,
    z: Integer,
    fd: Vec<Integer>,
    zd: Integer,
}

/// Generates a non-interactive zero-knowledge proof of a secret shuffle
pub fn prove(
    group: &schnorr::Group,
    com: &CommitmentScheme,
    l: &Integer,
    m: &[Integer],
    pi: &Permutation,
    r: &Integer,
) -> Proof {
    let g = group.generator();
    let p = group.modulus();
    let q = group.order();
    let n = m.len();
    let mut rng = thread_rng();

    let x = x_challenge(m, l);

    let d: Vec<_> = rng.sample_iter(&Modulo(q)).take(n).collect();

    let mut delta = Vec::with_capacity(n);
    delta.push(d[0].clone());
    delta.extend(rng.sample_iter(&Modulo(q)).take(n - 2));
    delta.push(Integer::new());

    let a: Vec<_> = (0..n)
        .map(|i| {
            pi.iter()
                .take(i)
                .map(|&p| Integer::from(&m[p] - &x))
                .fold(Integer::from(1), |acc, x| acc * x)
        })
        .collect();

    let (cd, rd) = com.commit_to(&d);
    let dd: Vec<_> = (1..n)
        .map(|i| Integer::from(-&delta[i - 1]) * &d[i])
        .collect();
    let (cdd, rdd) = com.commit_to(&dd);
    let da: Vec<_> = (1..n)
        .map(|i| {
            &delta[i]
                - Integer::from(&m[pi[i]] - &x) * &delta[i - 1]
                - Integer::from(&a[i - 1] * &d[i])
        })
        .collect();
    let (cda, rda) = com.commit_to(&da);

    let e = e_challenge(&cd, &cdd, &cda, &x);

    let f: Vec<_> = pi
        .iter()
        .zip(d.iter())
        .map(|(&p, d)| Integer::from(&e * &m[p]) + d)
        .collect();
    let z = &e * r + rd;

    let fd: Vec<_> = (1..n)
        .map(|i| {
            &e * (&delta[i]
                - Integer::from(&m[pi[i]] - &x) * &delta[i - 1]
                - Integer::from(&a[i - 1] * &d[i]))
                - Integer::from(&delta[i - 1] * &d[i])
        })
        .collect();
    let zd = &e * rda + rdd;

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

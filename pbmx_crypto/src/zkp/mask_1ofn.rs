//! Zero-knowledge proof of equality of discrete logarithms

use crate::{
    group::Group,
    hash::Hash,
    num::{fpowm, Modulo},
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Non-interactive proof result
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    c: Vec<Integer>,
    r: Vec<Integer>,
}

/// Generates a witness hidding non-interactive zero-knowledge proof that an i
/// exists such that log_g(x) = log_h(y/m_i)
#[allow(clippy::too_many_arguments)]
pub fn prove(
    group: &Group,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    m: &[Integer],
    idx: usize,
    alpha: &Integer,
) -> Proof {
    let mut rng = thread_rng();

    let p = group.modulus();
    let q = group.order();

    let (vw, t): (Vec<_>, Vec<_>) = m
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let v = rng.sample(&Modulo(q));
            let w = if i == idx {
                Integer::new()
            } else {
                rng.sample(&Modulo(q))
            };
            let a = fpowm::pow_mod(g, &v, p).unwrap();
            let b = fpowm::pow_mod(h, &v, p).unwrap();
            let t0 = Integer::from(x.pow_mod_ref(&w, p).unwrap()) * &a % p;
            let ydm = y * Integer::from(m.invert_ref(p).unwrap()) % p;
            let t1 = Integer::from(ydm.pow_mod_ref(&w, p).unwrap()) * &b % p;
            ((v, w), (t0, t1))
        })
        .unzip();
    let (v, w): (Vec<_>, Vec<_>) = vw.into_iter().unzip();

    let cx = challenge(&t, x, y, g, h, m);
    let w_sum = w.iter().sum::<Integer>();
    let mut c: Vec<_> = w;
    c[idx] = (cx - w_sum) % q;

    let mut r = v;
    r[idx] = (r[idx].clone() - &c[idx] * alpha) % q;

    Proof { c, r }
}

/// Verifies a witness hidding non-interactive zero-knowledge proof that an i
/// exists such that log_g(x) = log_h(y/m_i)
pub fn verify(
    group: &Group,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    m: &[Integer],
    proof: &Proof,
) -> bool {
    let p = group.modulus();
    let q = group.order();

    if proof.r.iter().any(|r| r.cmp_abs(q) != Ordering::Less) {
        return false;
    }

    let xc = proof
        .c
        .iter()
        .map(|c| Integer::from(x.pow_mod_ref(c, p).unwrap()));
    let gr = proof.r.iter().map(|r| fpowm::pow_mod(g, &r, p).unwrap());
    let t0 = xc.zip(gr).map(|(xc, gr)| gr * xc % p);

    let ydmc = proof.c.iter().zip(m.iter()).map(|(c, m)| {
        let ydm = y * Integer::from(m.invert_ref(p).unwrap()) % p;
        ydm.pow_mod(c, p).unwrap()
    });
    let hr = proof.r.iter().map(|r| fpowm::pow_mod(h, &r, p).unwrap());
    let t1 = ydmc.zip(hr).map(|(ydmc, hr)| hr * ydmc % p);
    let t: Vec<_> = t0.zip(t1).collect();

    let c1 = challenge(&t, x, y, g, h, m);
    let c_sum = proof.c.iter().sum::<Integer>() % q;

    c_sum == c1
}

fn challenge(
    t: &[(Integer, Integer)],
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    m: &[Integer],
) -> Integer {
    let mut hash = Hash::new();
    for (t0, t1) in t {
        hash = hash
            .chain(&t0.to_digits(Order::MsfBe))
            .chain(&t1.to_digits(Order::MsfBe));
    }
    hash = hash
        .chain(&x.to_digits(Order::MsfBe))
        .chain(&y.to_digits(Order::MsfBe))
        .chain(&g.to_digits(Order::MsfBe))
        .chain(&h.to_digits(Order::MsfBe));
    for m in m {
        hash = hash.chain(&m.to_digits(Order::MsfBe));
    }
    Integer::from_digits(&hash.result(), Order::MsfBe)
}

#[cfg(test)]
mod test {
    use super::{prove, verify};
    use crate::{
        group::Groups,
        num::{fpowm, Bits},
    };
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
        let g = group.element(&rng.sample(&Bits(128)));
        let h = group.element(&rng.sample(&Bits(128)));
        let p = group.modulus();

        let m: Vec<_> = (1..8).map(Integer::from).collect();
        let idx = rng.gen_range(1, 7);
        let r = rng.sample(&Bits(128));
        let x = fpowm::pow_mod(&g, &r, p).unwrap();
        let y = fpowm::pow_mod(&h, &r, p).unwrap() * &m[idx] % p;
        let mut proof = prove(&group, &x, &y, &g, &h, &m, idx, &r);

        let ok = verify(&group, &x, &y, &g, &h, &m, &proof);
        assert!(
            ok,
            "proof isn't valid\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x, y, g, h, idx, proof
        );

        // break the proof
        proof.r[0] += 1;
        let ok = verify(&group, &x, &y, &g, &h, &m, &proof);
        assert!(
            !ok,
            "invalid proof was accepted\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x,
            y,
            g, h,
            idx,
            proof
        );
    }
}

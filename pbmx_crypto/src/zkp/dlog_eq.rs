//! Chaum and Pedersen's zero-knowledge proof of equality of discrete logarithms

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
#[derive(Debug)]
pub struct Proof {
    c: Integer,
    r: Integer,
}

/// Generates a non-interactive zero-knowledge proof that log_g(x) = log_h(y)
pub fn prove(
    group: &Group,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    alpha: &Integer,
) -> Proof {
    let p = group.modulus();
    let q = group.order();
    let omega = thread_rng().sample(&Modulo(q));
    let a = fpowm::pow_mod(g, &omega, p).unwrap();
    let b = fpowm::pow_mod(h, &omega, p).unwrap();

    let c = challenge(&a, &b, x, y, g, h);
    let r = (&omega - Integer::from(&c * alpha)) % q;
    Proof { c, r }
}

/// Verifies a non-interactive zero-knowledge proof that log_g(x) = log_h(y)
#[allow(clippy::too_many_arguments)]
pub fn verify(
    group: &Group,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    proof: &Proof,
) -> bool {
    let p = group.modulus();
    let q = group.order();

    if proof.r.cmp_abs(q) != Ordering::Less {
        return false;
    }

    let xc = Integer::from(x.pow_mod_ref(&proof.c, p).unwrap());
    let gr = fpowm::pow_mod(g, &proof.r, p).unwrap();
    let a = gr * xc % p;

    let yc = Integer::from(y.pow_mod_ref(&proof.c, p).unwrap());
    let hr = fpowm::pow_mod(h, &proof.r, p).unwrap();
    let b = hr * yc % p;

    let c1 = challenge(&a, &b, x, y, g, h);

    proof.c == c1
}

fn challenge(
    a: &Integer,
    b: &Integer,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
) -> Integer {
    Integer::from_digits(
        &Hash::new()
            .chain(&a.to_digits(Order::MsfBe))
            .chain(&b.to_digits(Order::MsfBe))
            .chain(&x.to_digits(Order::MsfBe))
            .chain(&y.to_digits(Order::MsfBe))
            .chain(&g.to_digits(Order::MsfBe))
            .chain(&h.to_digits(Order::MsfBe))
            .result(),
        Order::MsfBe,
    )
}

#[cfg(test)]
mod test {
    use super::{prove, verify};
    use crate::{
        group::Groups,
        num::{fpowm, Bits},
    };
    use rand::{thread_rng, Rng};

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

        let i = rng.sample(&Bits(128));
        let x = fpowm::pow_mod(&g, &i, p).unwrap();
        let y = fpowm::pow_mod(&h, &i, p).unwrap();
        let mut proof = prove(&group, &x, &y, &g, &h, &i);

        let ok = verify(&group, &x, &y, &g, &h, &proof);
        assert!(
            ok,
            "proof isn't valid\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\talpha = {}\n\tproof = {:?}",
            x,
            y,
            g,
            h,
            i,
            proof
        );

        // break the proof
        proof.c += 1;
        let ok = verify(&group, &x, &y, &g, &h, &proof);
        assert!(
            !ok,
            "invalid proof was accepted\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\talpha = {}\n\tproof = {:?}",
            x,
            y,
            g,
            h,
            i,
            proof
        );
    }
}

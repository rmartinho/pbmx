use super::{Proof, Vtmf};
use crate::{crypto::hash::Hash, num::integer::Modulo};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

pub fn prove(
    vtmf: &Vtmf,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    alpha: &Integer,
) -> Proof {
    let q = vtmf.g.order();
    let omega = thread_rng().sample(&Modulo(q));
    let a = vtmf.g.element(&omega);
    let b = vtmf.fpowm.pow_mod(&omega).unwrap();

    let c = challenge(&a, &b, x, y, g, h);
    let r = (&omega - Integer::from(&c * alpha)) % q;
    (c, r)
}

pub fn verify(vtmf: &Vtmf, x: &Integer, y: &Integer, g: &Integer, h: &Integer, cr: &Proof) -> bool {
    let p = vtmf.g.modulus();
    let q = vtmf.g.order();
    let (ref c, ref r) = cr;

    if r.cmp_abs(q) != Ordering::Less {
        return false;
    }

    let xc = Integer::from(x.pow_mod_ref(c, p).unwrap());
    let a = vtmf.g.element(r) * xc % p;

    let yc = Integer::from(y.pow_mod_ref(c, p).unwrap());
    let b = vtmf.fpowm.pow_mod(r).unwrap() * yc % p;

    let c1 = challenge(&a, &b, x, y, g, h);

    *c == c1
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

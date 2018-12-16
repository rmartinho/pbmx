use super::Vtmf;
use crate::{crypto::hash::Hash, num::integer::Modulo};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Zero-knowledge proof of equality of discrete logarithms
pub type Proof = (Integer, Integer);

pub fn prove(
    vtmf: &Vtmf,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    alpha: &Integer,
) -> Proof {
    let p = vtmf.g.modulus();
    let q = vtmf.g.order();
    let omega = thread_rng().sample(&Modulo(q));
    let a = Integer::from(g.pow_mod_ref(&omega, p).unwrap());
    let b = Integer::from(h.pow_mod_ref(&omega, p).unwrap());

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
    let a = Integer::from(g.pow_mod_ref(&r, p).unwrap()) * xc % p;

    let yc = Integer::from(y.pow_mod_ref(c, p).unwrap());
    let b = Integer::from(h.pow_mod_ref(&r, p).unwrap()) * yc % p;

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

#[cfg(test)]
mod test {
    use super::{prove, verify};
    use crate::{
        crypto::{key::Keys, vtmf::KeyExchange},
        num::{integer::Bits, schnorr::Schnorr},
    };
    use rand::{thread_rng, Rng};

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();
        let dist = Schnorr {
            field_bits: 2048,
            group_bits: 1024,
            iterations: 64,
        };
        let group = rng.sample(&dist);
        let (_, pk1) = rng.sample(&Keys(&group));
        let (_, pk2) = rng.sample(&Keys(&group));
        let mut kex = KeyExchange::new(group, 3);
        let _ = kex.generate_key().unwrap();
        kex.update_key(pk1).unwrap();
        kex.update_key(pk2).unwrap();
        let vtmf = kex.finalize().unwrap();

        let i = rng.sample(&Bits(128));
        let x = vtmf.g.element(&i);
        let y = vtmf.fpowm.pow_mod(&i).unwrap();
        let mut proof = prove(&vtmf, &x, &y, vtmf.g.generator(), &vtmf.pk.h, &i);

        let ok = verify(&vtmf, &x, &y, vtmf.g.generator(), &vtmf.pk.h, &proof);
        assert!(
            ok,
            "proof isn't valid\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\talpha = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            i,
            proof
        );

        // break the proof
        proof.1 += 1;
        let ok = verify(&vtmf, &x, &y, vtmf.g.generator(), &vtmf.pk.h, &proof);
        assert!(
            !ok,
            "invalid proof was accepted\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\talpha = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            i,
            proof
        );
    }
}

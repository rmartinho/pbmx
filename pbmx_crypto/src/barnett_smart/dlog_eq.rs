use super::Vtmf;
use crate::{
    hash::Hash,
    num::{fpowm, integer::Modulo},
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Zero-knowledge proof of equality of discrete logarithms
pub type Proof = (Integer, Integer);

#[allow(clippy::too_many_arguments)]
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
    let a = fpowm::pow_mod(g, &omega, p).unwrap();
    let b = fpowm::pow_mod(h, &omega, p).unwrap();

    let c = challenge(&a, &b, x, y, g, h);
    let r = (&omega - Integer::from(&c * alpha)) % q;
    (c, r)
}

#[allow(clippy::too_many_arguments)]
pub fn verify(vtmf: &Vtmf, x: &Integer, y: &Integer, g: &Integer, h: &Integer, cr: &Proof) -> bool {
    let p = vtmf.g.modulus();
    let q = vtmf.g.order();
    let (ref c, ref r) = cr;

    if r.cmp_abs(q) != Ordering::Less {
        return false;
    }

    let xc = Integer::from(x.pow_mod_ref(c, p).unwrap());
    let gr = fpowm::pow_mod(g, &r, p).unwrap();
    let a = gr * xc % p;

    let yc = Integer::from(y.pow_mod_ref(c, p).unwrap());
    let hr = fpowm::pow_mod(h, &r, p).unwrap();
    let b = hr * yc % p;

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
        barnett_smart::KeyExchange,
        elgamal::Keys,
        num::{fpowm, integer::Bits},
        schnorr,
    };
    use rand::{thread_rng, Rng};

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();
        let dist = schnorr::Groups {
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

        let g = vtmf.g.generator();
        let p = vtmf.g.modulus();
        let h = &vtmf.pk.h;

        let i = rng.sample(&Bits(128));
        let x = fpowm::pow_mod(g, &i, p).unwrap();
        let y = fpowm::pow_mod(h, &i, p).unwrap();
        let mut proof = prove(&vtmf, &x, &y, g, h, &i);

        let ok = verify(&vtmf, &x, &y, g, h, &proof);
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
        proof.1 += 1;
        let ok = verify(&vtmf, &x, &y, g, h, &proof);
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

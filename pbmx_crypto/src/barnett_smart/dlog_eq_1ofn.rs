use super::Vtmf;
use crate::{
    hash::Hash,
    num::{fpowm::FastPowModTable, integer::Modulo},
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Zero-knowledge proof of knowledge of 1-of-n discrete logarithms
pub type Proof = (Vec<Integer>, Vec<Integer>);

#[allow(clippy::too_many_arguments)]
pub fn prove(
    vtmf: &Vtmf,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    m: &[Integer],
    idx: usize,
    alpha: &Integer,
    fpowm_g: Option<&FastPowModTable>,
    fpowm_h: Option<&FastPowModTable>,
) -> Proof {
    let mut rng = thread_rng();

    let p = vtmf.g.modulus();
    let q = vtmf.g.order();

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
            let a = if let Some(g) = fpowm_g {
                g.pow_mod(&v).unwrap()
            } else {
                g.pow_mod_ref(&v, p).unwrap().into()
            };
            let b = if let Some(h) = fpowm_h {
                h.pow_mod(&v).unwrap()
            } else {
                h.pow_mod_ref(&v, p).unwrap().into()
            };
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

    (c, r)
}

#[allow(clippy::too_many_arguments)]
pub fn verify(
    vtmf: &Vtmf,
    x: &Integer,
    y: &Integer,
    g: &Integer,
    h: &Integer,
    m: &[Integer],
    cr: &Proof,
    fpowm_g: Option<&FastPowModTable>,
    fpowm_h: Option<&FastPowModTable>,
) -> bool {
    let p = vtmf.g.modulus();
    let q = vtmf.g.order();
    let (ref c, ref r) = cr;

    if r.iter().any(|r| r.cmp_abs(q) != Ordering::Less) {
        return false;
    }

    let xc = c
        .iter()
        .map(|c| Integer::from(x.pow_mod_ref(c, p).unwrap()));
    let gr = r.iter().map(|r| {
        if let Some(g) = fpowm_g {
            g.pow_mod(&r).unwrap()
        } else {
            g.pow_mod_ref(&r, p).unwrap().into()
        }
    });
    let t0 = xc.zip(gr).map(|(xc, gr)| gr * xc % p);

    let ydmc = c.iter().zip(m.iter()).map(|(c, m)| {
        let ydm = y * Integer::from(m.invert_ref(p).unwrap()) % p;
        ydm.pow_mod(c, p).unwrap()
    });
    let hr = r.iter().map(|r| {
        if let Some(h) = fpowm_h {
            h.pow_mod(&r).unwrap()
        } else {
            h.pow_mod_ref(&r, p).unwrap().into()
        }
    });
    let t1 = ydmc.zip(hr).map(|(ydmc, hr)| hr * ydmc % p);
    let t: Vec<_> = t0.zip(t1).collect();

    let c1 = challenge(&t, x, y, g, h, m);
    let c_sum = c.iter().sum::<Integer>() % q;

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
    use crate::{barnett_smart::KeyExchange, elgamal::Keys, num::integer::Bits, schnorr};
    use rand::{thread_rng, Rng};
    use rug::Integer;

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

        let m: Vec<_> = (1..8).map(Integer::from).collect();
        let idx = rng.gen_range(1, 7);
        let r = rng.sample(&Bits(128));
        let x = vtmf.g.element(&r);
        let y = vtmf.fpowm.pow_mod(&r).unwrap() * &m[idx] % vtmf.g.modulus();
        let mut proof = prove(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            idx,
            &r,
            None,
            None,
        );

        let ok = verify(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            &proof,
            None,
            None,
        );
        assert!(
            ok,
            "proof isn't valid\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            idx,
            proof
        );

        // break the proof
        proof.1[0] += 1;
        let ok = verify(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            &proof,
            None,
            None,
        );
        assert!(
            !ok,
            "invalid proof was accepted\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            idx,
            proof
        );
    }

    #[test]
    fn prove_and_verify_agree_with_fpowm() {
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

        let m: Vec<_> = (1..8).map(Integer::from).collect();
        let idx = rng.gen_range(1, 8);
        let r = rng.sample(&Bits(128));
        let x = vtmf.g.element(&r);
        let y = vtmf.fpowm.pow_mod(&r).unwrap() * &m[idx] % vtmf.g.modulus();
        let mut proof = prove(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            idx,
            &r,
            Some(&vtmf.g.fpowm),
            Some(&vtmf.fpowm),
        );

        let ok = verify(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            &proof,
            Some(&vtmf.g.fpowm),
            Some(&vtmf.fpowm),
        );
        assert!(
            ok,
            "proof isn't valid\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            idx,
            proof
        );

        // break the proof
        proof.1[0] += 1;
        let ok = verify(
            &vtmf,
            &x,
            &y,
            vtmf.g.generator(),
            &vtmf.pk.h,
            &m,
            &proof,
            Some(&vtmf.g.fpowm),
            Some(&vtmf.fpowm),
        );
        assert!(
            !ok,
            "invalid proof was accepted\n\tx = {}\n\ty = {}\n\tg = {}\n\th = {}\n\tidx = {}\n\tproof = {:?}",
            x,
            y,
            vtmf.g.generator(),
            vtmf.pk.h,
            idx,
            proof
        );
    }
}

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
    ee: &[Mask],
    pi: &Permutation,
    ri: &[Integer],
) -> Proof {
    assert!(ee.len() == ri.len());

    let g = group.generator();
    let p = group.modulus();
    let q = group.order();
    let n = ee.len();
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
        .zip(ee.iter())
        .map(|(d, (e1, e2))| {
            let x1 = fpowm::pow_mod(e1, d, p).unwrap() * &c1 % p;
            let x2 = fpowm::pow_mod(e2, d, p).unwrap() * &c2 % p;
            (x1, x2)
        })
        .fold(
            (Integer::from(1), Integer::from(1)),
            |(a1, a2), (e1, e2)| (a1 * e1, a2 * e2),
        );

    let ti = t_challenge(&c, &cd, &ed, ee);
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
pub fn verify(e: &[Mask], ee: &[Mask], proof: &Proof) -> bool {
    let g = proof.com.group().generator();
    let p = proof.com.group().modulus();
    let q = proof.com.group().order();
    let h = proof.com.shared_secret();
    let n = ee.len();

    let t = t_challenge(&proof.c, &proof.cd, &proof.ed, ee);
    let l = l_challenge(&proof.fi, &proof.z, &t);

    let cld = fpowm::pow_mod(&proof.c, &l, p).unwrap() * &proof.cd % p;
    let m: Vec<_> = (0..n)
        .map(|i| (Integer::from(i + 1) * &l + &t[i]) % q)
        .collect();

    println!("a");
    if !known_shuffle::verify(&proof.com, &l, &cld, &m, &proof.skc) {
        return false;
    }

    println!("a");
    if !proof.com.group().has_element(&proof.c) {
        return false;
    }
    println!("a");
    if !proof.com.group().has_element(&proof.cd) {
        return false;
    }

    println!("a");
    if fpowm::pow_mod(&proof.ed.0, q, p).unwrap() != 1 {
        return false;
    }
    println!("a");
    if fpowm::pow_mod(&proof.ed.1, q, p).unwrap() != 1 {
        return false;
    }

    println!("a");
    if proof
        .fi
        .iter()
        .any(|f| (f.significant_bits() as usize) < Hash::output_size() || f >= q)
    {
        return false;
    }

    println!("a");
    if proof.z <= 0 || proof.z >= *q {
        return false;
    }

    let et = e
        .iter()
        .zip(t.iter())
        .map(|(e, t)| {
            let mt = &t.as_neg();
            (
                fpowm::pow_mod(&e.0, &mt, p).unwrap(),
                fpowm::pow_mod(&e.1, &mt, p).unwrap(),
            )
        })
        .fold((Integer::from(1), Integer::from(1)), |acc, i| {
            (acc.0 * i.0 % p, acc.1 * i.1 % p)
        });

    let efe = ee
        .iter()
        .zip(proof.fi.iter())
        .map(|(ee, f)| {
            (
                fpowm::pow_mod(&ee.0, f, p).unwrap() * &proof.ed.0,
                fpowm::pow_mod(&ee.1, f, p).unwrap() * &proof.ed.1,
            )
        })
        .fold((Integer::from(1), Integer::from(1)), |acc, i| {
            (acc.0 * i.0 % p, acc.1 * i.1 % p)
        });

    let epk = (
        fpowm::pow_mod(g, &proof.z, p).unwrap(),
        fpowm::pow_mod(h, &proof.z, p).unwrap(),
    );
    let etf = (et.0 * efe.0, et.1 * efe.1);

    println!("a");
    etf == epk
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
mod test {
    use super::{prove, verify};
    use crate::{
        num::{fpowm, Bits, Modulo},
        perm::Shuffles,
        schnorr,
    };
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
        let g = group.generator();
        let p = group.modulus();
        let q = group.order();
        let h = group.element(&rng.sample(&Bits(128)));

        let m: Vec<_> = (1..=8).map(Integer::from).collect();
        let mm: Vec<_> = m
            .iter()
            .map(|i| {
                let r = rng.sample(&Modulo(q));
                (
                    fpowm::pow_mod(g, &r, p).unwrap(),
                    fpowm::pow_mod(&h, &r, p).unwrap() * i,
                )
            })
            .collect();
        let (mut mp, rp): (Vec<_>, Vec<_>) = mm
            .iter()
            .map(|c| {
                let r = rng.sample(&Modulo(q));
                (
                    (
                        fpowm::pow_mod(g, &r, p).unwrap() * &c.0,
                        fpowm::pow_mod(&h, &r, p).unwrap() * &c.1,
                    ),
                    r,
                )
            })
            .unzip();
        let pi = rng.sample(&Shuffles(8));
        pi.apply_to(&mut mp);

        let mut proof = prove(&group, &h, &mp, &pi, &rp);

        let ok = verify(&mm, &mp, &proof);
        assert!(
            ok,
            /*    "proof isn't valid\n\tcom = {:#?}\n\tc = {}\n\tm = {:?}\n\tp = {:#?}\n\tr
             * = {}\n\tproof = {:?}",    com,
             *    c,
             *    m,
             *    pi,
             *    r,
             *    proof */
        );

        // break the proof
        proof.z += 1;
        let ok = verify(&mm, &mp, &proof);
        assert!(
            !ok,
            /*    "invalid proof was accepted\n\tcom = {:#?}\n\tc = {}\n\tm = {:?}\n\tp =
             * {:#?}\n\tr = {}\n\tproof = {:?}",    com,
             *    c,
             *    m,
             *    pi,
             *    r,
             *    proof */
        );
    }
}

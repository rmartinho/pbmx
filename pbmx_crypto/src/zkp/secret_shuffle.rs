//! Groth's verifiable secret shuffle of homomorphic encryptions

use crate::{
    commit::CommitmentScheme,
    group::Group,
    hash::{hash_iter, Hash},
    num::{fpowm, Bits},
    perm::Permutation,
    vtmf::Mask,
    zkp::known_shuffle,
};
use digest::Digest;
use rand::{thread_rng, Rng};
use rug::{integer::Order, Integer};
use std::cmp::Ordering;

/// Non-interactive proof result
#[derive(Debug, Serialize, Deserialize)]
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
pub fn prove(group: &Group, h: &Integer, ee: &[Mask], pi: &Permutation, ri: &[Integer]) -> Proof {
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

    let ed = d
        .iter()
        .zip(ee.iter())
        .map(|(d, (e1, e2))| {
            (
                fpowm::pow_mod(e1, d, p).unwrap(),
                fpowm::pow_mod(e2, d, p).unwrap(),
            )
        })
        .fold(
            (Integer::from(1), Integer::from(1)),
            |(a1, a2), (e1, e2)| (a1 * e1 % p, a2 * e2 % p),
        );
    let c1 = fpowm::pow_mod(g, &rd, p).unwrap();
    let c2 = fpowm::pow_mod(h, &rd, p).unwrap();
    let ed = (ed.0 * &c1 % p, ed.1 * &c2 % p);

    let ti = t_challenge(&c, &cd, &ed, ee);
    let fi: Vec<_> = pi
        .iter()
        .zip(d.iter())
        .map(|(p, d)| Integer::from(&ti[*p] - d) % q)
        .collect();
    let z = (pi
        .iter()
        .zip(ri.iter())
        .map(|(p, r)| Integer::from(&ti[*p] * r) % q)
        .sum::<Integer>()
        + &rd)
        % q;

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

    let ti = t_challenge(&proof.c, &proof.cd, &proof.ed, ee);
    let l = l_challenge(&proof.fi, &proof.z, &ti);

    let cld = fpowm::pow_mod(&proof.c, &l, p).unwrap() * &proof.cd % p;
    let cldf = cld * proof.com.commit_by(&proof.fi, &Integer::new());
    let m: Vec<_> = (0..n)
        .map(|i| (&l * Integer::from(i + 1) % q + &ti[i]) % q)
        .collect();

    if !known_shuffle::verify(&proof.com, &l, &cldf, &m, &proof.skc) {
        println!("skc");
        return false;
    }

    if !proof.com.group().has_element(&proof.c) {
        println!("c");
        return false;
    }
    if !proof.com.group().has_element(&proof.cd) {
        println!("cd");
        return false;
    }

    if !proof.com.group().has_element(&proof.ed.0) {
        println!("ed0");
        return false;
    }

    let bad_f = |f: &Integer| {
        (f.significant_bits() as usize) < Hash::output_size() || f.cmp_abs(q) != Ordering::Less
    };
    if proof.fi.iter().any(bad_f) {
        println!("fi");
        return false;
    }

    if proof.z.cmp_abs(q) != Ordering::Less {
        println!("z");
        return false;
    }

    let et = e
        .iter()
        .zip(ti.iter())
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
                fpowm::pow_mod(&ee.0, f, p).unwrap(),
                fpowm::pow_mod(&ee.1, f, p).unwrap(),
            )
        })
        .fold(
            (Integer::from(1), Integer::from(1)),
            |acc, i: (Integer, Integer)| (acc.0 * i.0 % p, acc.1 * i.1 % p),
        );
    let efed = (efe.0 * &proof.ed.0 % p, efe.1 * &proof.ed.1 % p);
    let etfd = (et.0 * efed.0 % p, et.1 * efed.1 % p);

    let ez = (
        fpowm::pow_mod(g, &proof.z, p).unwrap(),
        fpowm::pow_mod(h, &proof.z, p).unwrap(),
    );

    etfd == ez
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

fn l_challenge(fi: &[Integer], z: &Integer, ti: &[Integer]) -> Integer {
    let mut hash = Hash::new();
    for f in fi {
        hash = hash.chain(&f.to_digits(Order::MsfBe));
    }
    hash = hash.chain(&z.to_digits(Order::MsfBe));
    for t in ti {
        hash = hash.chain(&t.to_digits(Order::MsfBe));
    }
    Integer::from_digits(&hash.result(), Order::MsfBe)
}

#[cfg(test)]
mod test {
    use super::{prove, verify};
    use crate::{
        group::Groups,
        num::{fpowm, Bits, Modulo},
        perm::Shuffles,
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
        let (mut mp, mut rp): (Vec<_>, Vec<_>) = mm
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
        pi.apply_to(&mut rp);

        let mut proof = prove(&group, &h, &mp, &pi, &rp);

        let ok = verify(&mm, &mp, &proof);
        assert!(ok,
            "proof isn't valid\n\tgroup = {:#?}\n\th = {}\n\tmm = {:?}\n\tmp = {:?}\n\tpi = {:#?}\n\trp = {:?}\n\tproof = {:?}",
            group,
            h,
            mm,
            mp,
            pi,
            rp,
            proof
        );

        // break the proof
        proof.z += 1;
        let ok = verify(&mm, &mp, &proof);
        assert!(!ok,
            "invalid proof was accepted\n\tgroup = {:#?}\n\th = {}\n\tmm = {:?}\n\tmp = {:?}\n\tpi = {:#?}\n\trp = {:?}\n\tproof = {:?}",
            group,
            h,
            mm,
            mp,
            pi,
            rp,
            proof
        );
    }
}

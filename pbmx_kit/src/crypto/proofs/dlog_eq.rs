//! Chaum and Pedersen's zero-knowledge proof of equality of discrete logarithms

mod proof {
    #![allow(missing_docs)]
    create_nipk! { proof, (x), (a, b, g, h) : a = (g * x), b = (h * x) }
}
pub use proof::proof::{Proof, Publics, Secrets};

#[cfg(test)]
mod tests {
    use super::{Proof, Publics, Secrets};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use merlin::Transcript;
    use rand::thread_rng;

    #[test]
    fn prove_and_verify_agree() {
        let mut rng = thread_rng();

        let g = &RistrettoPoint::random(&mut rng);
        let h = &RistrettoPoint::random(&mut rng);
        let x = &Scalar::random(&mut rng);

        let a = &(g * x);
        let b = &(h * x);
        let publics = Publics { a, b, g, h };
        let secrets = Secrets { x };

        let proof = Proof::create(&mut Transcript::new(b"test"), publics, secrets);

        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Ok(()));

        // break the proof
        let proof = Proof::create(&mut Transcript::new(b"test"), publics, Secrets {
            x: &Scalar::one(),
        });
        let verified = proof.verify(&mut Transcript::new(b"test"), publics);
        assert_eq!(verified, Err(()));
    }
}

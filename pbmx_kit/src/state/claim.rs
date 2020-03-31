//! Claim status tracking

use crate::{
    chain::{Id, Payload},
    crypto::{
        keys::Fingerprint,
        map,
        vtmf::{Stack, Vtmf},
    },
    state::StackMap,
};
use digest::generic_array::typenum::U32;
use std::collections::HashMap;

/// A claim that requires a interactive verification
#[derive(Debug, Clone)]
pub struct Claim {
    payload: Payload,
    status: ClaimStatus,
}

create_hash! {
    /// The hash used for claim IDs
    pub struct ClaimHash(Hash<U32>) = b"pbmx-claim-id";
}

impl Claim {
    /// Creates a new claim with unverified status
    pub fn new(payload: Payload) -> Self {
        assert!(payload.is_claim());

        Self {
            payload,
            status: ClaimStatus::Unverified(HashMap::new()),
        }
    }

    /// Gets this claim's ID
    pub fn id(&self) -> Id {
        self.payload.id()
    }

    /// Gets this claim's payload
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Checks whether this claim has been verified
    pub fn is_verified(&self) -> bool {
        if let ClaimStatus::Verified = self.status {
            true
        } else {
            false
        }
    }

    /// Marks this claim as verified
    pub fn verify(&mut self, vtmf: &Vtmf, stacks: &StackMap) {
        match self.status {
            ClaimStatus::Unverified(ref shares) => {
                if shares.len() < vtmf.parties() {
                    return;
                }
                let proof_stack = match stacks.get_by_id(&self.proof_stack_id()) {
                    Some(stack) => stack.clone(),
                    None => return,
                };
                let target_stack = match stacks.get_by_id(&self.target_stack_id()) {
                    Some(stack) => stack.clone(),
                    None => return,
                };

                let mut open_proof: Vec<_> = shares
                    .values()
                    .map(|p| match p {
                        Payload::PublishShares(_, shares, _) => shares,
                        _ => unreachable!(),
                    })
                    .fold(proof_stack, |mut acc, s| {
                        acc.iter_mut().zip(s.iter()).for_each(|(m, d)| {
                            *m = vtmf.unmask(&m, d);
                        });
                        acc
                    })
                    .iter()
                    .map(|m| map::from_curve(&vtmf.unmask_open(&m)))
                    .collect();
                open_proof.sort();

                let mut open_target: Vec<_> = target_stack
                    .iter()
                    .map(|m| map::from_curve(&vtmf.unmask_open(&m)))
                    .collect();
                open_target.sort();

                if open_proof != open_target {
                    println!("proof {:?} target {:?}", open_proof, open_target);
                    return;
                }
            }
            _ => return,
        }
        self.status = ClaimStatus::Verified;
    }

    /// Checks whether a payload is a verification share for this claim
    pub fn needs_share(&self, payload: &Payload) -> bool {
        use Payload::*;
        let share_id = if let PublishShares(id, ..) = payload {
            id
        } else {
            return false;
        };
        &self.proof_stack_id() == share_id
    }

    fn proof_stack_id(&self) -> Id {
        use Payload::*;
        match &self.payload {
            ProveSubset(_, _, proof) => Stack(proof.shuffle.to_vec()).id(),
            ProveSuperset(_, _, proof) => Stack(proof.shuffle[..proof.n].to_vec()).id(),
            ProveDisjoint(_, _, _, proof) => Stack(proof.shuffle.to_vec()).id(),
            _ => unreachable!(),
        }
    }

    fn target_stack_id(&self) -> Id {
        use Payload::*;
        *match &self.payload {
            ProveSubset(_, id, _) => id,
            ProveSuperset(_, id, _) => id,
            ProveDisjoint(_, _, id, _) => id,
            _ => unreachable!(),
        }
    }

    /// Checks whether a share for a given player has been provided
    pub fn has_share(&self, fingerprint: &Fingerprint) -> bool {
        if let ClaimStatus::Unverified(map) = &self.status {
            map.contains_key(fingerprint)
        } else {
            true
        }
    }

    /// Gets the verification shares attached to this claim
    pub fn shares(&'_ self) -> impl Iterator<Item = &'_ Payload> {
        if let ClaimStatus::Unverified(map) = &self.status {
            map.values()
        } else {
            unimplemented!()
        }
    }

    /// Adds a verification share payload
    pub fn add_share(&mut self, fingerprint: Fingerprint, payload: Payload) {
        if let ClaimStatus::Unverified(map) = &mut self.status {
            map.insert(fingerprint, payload);
        }
    }
}

/// The status of a claim
#[derive(Debug, Clone)]
pub enum ClaimStatus {
    /// The claim was verified
    Verified,
    /// The claim was not completely verified
    ///
    /// Some of the payloads required for verification are available.
    Unverified(HashMap<Id, Payload>),
}

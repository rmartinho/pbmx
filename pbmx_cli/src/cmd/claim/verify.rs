use crate::{state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::{
    chain::{Payload, Payload::*},
    crypto::vtmf::Stack,
};

pub fn run(_: &ArgMatches, _: &Config) -> Result<()> {
    let mut state = State::read(true)?;

    let fp = &state.base.vtmf.public_key().fingerprint();
    for claim in state.base.claims.values() {
        if !claim.is_verified() && !claim.has_share(&fp) {
            let shuffle: Stack = match claim.payload() {
                ProveSubset(_, _, proof) => Ok(&proof.shuffle[..]),
                ProveSuperset(_, _, proof) => Ok(&proof.shuffle[..proof.n]),
                ProveDisjoint(_, _, _, proof) => Ok(&proof.shuffle[..]),
                _ => Err(Error::InvalidData),
            }?
            .clone()
            .into();
            let (s, p): (Vec<_>, Vec<_>) = shuffle
                .iter()
                .map(|m| state.base.vtmf.unmask_share(m))
                .unzip();

            let id1 = shuffle.id();
            state.payloads.push(Payload::PublishShares(id1, s, p));
            println!("{} {:16}", " + Publish secrets".green().bold(), id1);
        }
    }

    state.save_payloads()?;
    Ok(())
}

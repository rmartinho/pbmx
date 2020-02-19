use super::full_unmask_stack;
use crate::{state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::{
    chain::Payload,
    crypto::{map, vtmf::Mask},
};
use std::collections::HashSet;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let sub_id = value_t!(m, "SUBSET", String)?;
    let sup_id = value_t!(m, "SUPERSET", String)?;

    let mut state = State::read(true)?;

    let sub = state
        .base
        .stacks
        .get_by_str(&sub_id)
        .ok_or(Error::InvalidData)?;
    let usub: HashSet<_> = full_unmask_stack(sub, &state)?.collect();

    let sup = state
        .base
        .stacks
        .get_by_str(&sup_id)
        .ok_or(Error::InvalidData)?;
    let usup: Vec<_> = full_unmask_stack(sup, &state)?.collect();

    let diff = usup
        .iter()
        .filter(|x| !usub.contains(x))
        .map(|&x| Mask::open(map::to_curve(x)))
        .collect();
    let proof = state.base.vtmf.prove_subset(&sub, &sup, &diff);
    let id1 = sub.id();
    let id2 = sup.id();
    state.payloads.push(Payload::ProveSubset(id1, id2, proof));
    println!(
        "{} {:16} \u{2286} {:16}",
        " + Prove subset".green().bold(),
        id1,
        id2
    );
    // TODO add initial verification payload

    state.save_payloads()?;
    Ok(())
}

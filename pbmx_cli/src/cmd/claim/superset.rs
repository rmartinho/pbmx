use super::full_unmask_stack;
use crate::{state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::chain::Payload;
use std::collections::HashSet;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let sup_id = value_t!(m, "SUPERSET", String)?;
    let sub_id = value_t!(m, "SUBSET", String)?;

    let mut state = State::read(true)?;

    let sup = state
        .base
        .stacks
        .get_by_str(&sup_id)
        .ok_or(Error::InvalidData)?;
    let usup: Vec<_> = full_unmask_stack(sup, &state)?.collect();

    let sub = state
        .base
        .stacks
        .get_by_str(&sub_id)
        .ok_or(Error::InvalidData)?;
    let usub: HashSet<_> = full_unmask_stack(sub, &state)?.collect();

    let idx: Vec<_> = usup
        .iter()
        .enumerate()
        .filter(|(_, x)| usub.contains(x))
        .map(|(i, _)| i)
        .collect();
    let proof = state.base.vtmf.prove_superset(&sup, &sub, &idx);
    let id1 = sup.id();
    let id2 = sub.id();
    state.payloads.push(Payload::ProveSuperset(id1, id2, proof));
    println!(
        "{} {:16} \u{2287} {:16}",
        " + Prove superset".green().bold(),
        id1,
        id2
    );
    // TODO add initial verification payload

    state.save_payloads()?;
    Ok(())
}

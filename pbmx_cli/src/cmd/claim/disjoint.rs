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
    let s1_id = value_t!(m, "STACK1", String)?;
    let s2_id = value_t!(m, "STACK2", String)?;
    let uni_id = value_t!(m, "UNIVERSE", String)?;

    let mut state = State::read(true)?;

    let s1 = state
        .base
        .stacks
        .get_by_str(&s1_id)
        .ok_or(Error::InvalidData)?;
    let us1: HashSet<_> = full_unmask_stack(s1, &state)?.collect();
    let s2 = state
        .base
        .stacks
        .get_by_str(&s2_id)
        .ok_or(Error::InvalidData)?;
    let us2: HashSet<_> = full_unmask_stack(s2, &state)?.collect();
    let uni = state
        .base
        .stacks
        .get_by_str(&uni_id)
        .ok_or(Error::InvalidData)?;
    let uuni: HashSet<_> = full_unmask_stack(uni, &state)?.collect();

    let extra = uuni
        .iter()
        .filter(|x| !us1.contains(x) && !us2.contains(x))
        .map(|&x| Mask::open(map::to_curve(x)))
        .collect();
    let proof = state.base.vtmf.prove_disjoint(&s1, &s2, &uni, &extra);
    let id1 = s1.id();
    let id2 = s2.id();
    state
        .payloads
        .push(Payload::ProveDisjoint(id1, id2, uni.id(), proof));
    println!(
        "{} {:16} \u{2260} {:16}",
        " + Prove disjoint".green().bold(),
        id1,
        id2
    );
    // TODO add initial verification payload

    state.save_payloads()?;
    Ok(())
}

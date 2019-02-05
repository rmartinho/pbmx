use crate::{
    error::{Error, Result},
    indices::parse_indices,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::{payload::Payload, Id};
use pbmx_curve::perm::{Permutation, Shuffles};
use rand::{thread_rng, Rng};

pub fn pile(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let in_ids = values_t!(m, "STACKS", String)?;
    let stacks: Vec<_> = in_ids
        .iter()
        .map(|id| {
            state
                .find_stack(&id)
                .ok_or(Error::InvalidData)
                .map(|x| x.0.to_vec())
        })
        .collect::<Result<_>>()?;
    let ids: Vec<_> = stacks.iter().map(|s| Id::of(s).unwrap()).collect();

    let tokens: Vec<_> = stacks.into_iter().flat_map(|s| s.into_iter()).collect();

    let id2 = Id::of(&tokens).unwrap();
    println!(
        "{} {:?} \u{21A3} {:16}",
        " + Pile stacks".green().bold(),
        in_ids,
        id2
    );
    state.payloads.push(Payload::PileStacks(ids, tokens));
    let name = value_t!(m, "TARGET", String).ok();
    if let Some(name) = name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, name);
        state.payloads.push(Payload::NameStack(id2, name));
    }

    state.save_payloads()?;
    Ok(())
}

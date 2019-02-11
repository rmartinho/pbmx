use crate::{indices::parse_indices, state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::perm::{Permutation, Shuffles};
use rand::{thread_rng, Rng};
use std::convert::TryFrom;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String)?;
    let indices = values_t!(m, "INDICES", String).ok();

    let mut state = State::read(true)?;

    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;

    let perm = if let Some(indices) = indices {
        let v: Vec<_> = indices
            .iter()
            .map(|s| parse_indices(s).ok_or(Error::InvalidData))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Permutation::try_from(v).map_err(|_| Error::InvalidData)?
    } else {
        thread_rng().sample(&Shuffles(stack.len()))
    };
    let (s, proof) = state.vtmf.mask_shuffle(&stack, &perm);

    let id1 = stack.id();
    let id2 = s.id();
    state.payloads.push(Payload::ShuffleStack(id1, s, proof));
    println!(
        "{} {:16} \u{224B} {:16}",
        " + Shuffle stack".green().bold(),
        id1,
        id2
    );
    if state.stacks.is_name(&id) {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, id);
        state.payloads.push(Payload::NameStack(id2, id.to_string()));
    }

    state.save_payloads()?;
    Ok(())
}

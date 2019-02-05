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

pub fn take(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = value_t!(m, "SOURCE", String)?;
    let (stack, _) = state.find_stack(&id).ok_or(Error::InvalidData)?;
    let indices = values_t!(m, "INDICES", String)?;
    let indices: Vec<_> = indices
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let tokens: Vec<_> = stack
        .iter()
        .enumerate()
        .filter_map(|(i, m)| if indices.contains(&i) { Some(*m) } else { None })
        .collect();

    let id1 = Id::of(&stack.to_vec()).unwrap();
    let id2 = Id::of(&tokens).unwrap();
    println!(
        "{} {:16}{:?} \u{219B} {:16}",
        " + Take tokens".green().bold(),
        id1,
        indices,
        id2
    );
    state
        .payloads
        .push(Payload::TakeStack(id1, indices, tokens));
    let name = value_t!(m, "TARGET", String).ok();
    if let Some(name) = name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, name);
        state.payloads.push(Payload::NameStack(id2, name));
    }

    state.save_payloads()?;
    Ok(())
}

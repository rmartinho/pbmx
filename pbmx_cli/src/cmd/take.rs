use crate::{
    error::{Error, Result},
    indices::parse_indices,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::vtmf::Stack;

pub fn take(m: &ArgMatches) -> Result<()> {
    let mut state = State::read(true)?;

    let id = value_t!(m, "SOURCE", String)?;
    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
    let indices = values_t!(m, "INDICES", String)?;
    let indices: Vec<_> = indices
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let tokens: Stack = stack
        .iter()
        .enumerate()
        .filter_map(|(i, m)| if indices.contains(&i) { Some(*m) } else { None })
        .collect();

    let id1 = stack.id();
    let id2 = tokens.id();
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

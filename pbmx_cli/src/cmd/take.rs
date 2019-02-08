use crate::{indices::parse_indices, state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::vtmf::Stack;

pub fn take(m: &ArgMatches, _: &Config) -> Result<()> {
    let id = value_t!(m, "SOURCE", String)?;
    let indices = values_t!(m, "INDICES", String)?;
    let target = value_t!(m, "TARGET", String).ok();
    let remove = m.is_present("REMOVE");

    let mut state = State::read(true)?;

    let stack = state
        .stacks
        .get_by_str(&id)
        .ok_or(Error::InvalidData)?
        .clone();
    let indices: Vec<_> = indices
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    if remove {
        if state.stacks.is_name(&id) {
            let rev_indices: Vec<_> = (0..stack.len()).filter(|i| !indices.contains(&i)).collect();
            take_impl(&stack, rev_indices, Some(id), &mut state)?;
        }
    }
    take_impl(&stack, indices, target, &mut state)?;

    state.save_payloads()?;
    Ok(())
}

pub fn take_impl(
    stack: &Stack,
    indices: Vec<usize>,
    target: Option<String>,
    state: &mut State,
) -> Result<()> {
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
    if let Some(target) = target {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, target);
        state.payloads.push(Payload::NameStack(id2, target));
    }

    Ok(())
}

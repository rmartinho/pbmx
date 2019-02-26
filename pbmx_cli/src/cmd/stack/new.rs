use crate::{
    indices::parse_indices, stack_map::display_stack_contents, state::State, Config, Error, Result,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::{
    map,
    vtmf::{Mask, Stack},
};
use std::collections::HashMap;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    let name = value_t!(m, "NAME", String).ok();
    let stack = values_t!(m, "TOKENS", String).unwrap_or_else(|_| vec![]);

    let mut state = State::read(true)?;

    let stack: Stack = stack
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .map(|i| Mask::open(map::to_curve(i as u64)))
        .collect();
    let id = stack.id();
    println!(
        "{} {}",
        " + Open stack".green().bold(),
        display_stack_contents(
            &stack.clone(),
            &HashMap::new(),
            &HashMap::new(),
            &state.vtmf,
            cfg
        )
    );
    state.payloads.push(Payload::OpenStack(stack));
    if let Some(name) = name {
        let name_change = state
            .stacks
            .get_by_name(&name)
            .map(|s| s.id() != id)
            .unwrap_or(true);
        if name_change {
            println!("{} {:16} {}", " + Name stack".green().bold(), id, name);
            state.payloads.push(Payload::NameStack(id, name));
        }
    }

    state.save_payloads()?;
    Ok(())
}

use crate::{stack_map::display_stack_contents, state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use std::collections::HashSet;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String).ok();

    let state = State::read(true)?;

    if let Some(id) = id {
        let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
        if state.stacks.is_name(&id) {
            print!("{} ", id.bold());
        }
        println!(
            "{}",
            display_stack_contents(&stack, &state.stacks.secrets, &state.vtmf, cfg)
        );
    } else {
        let mut named = HashSet::new();
        let mut names: Vec<_> = state.stacks.names().collect();
        names.sort();
        for n in names {
            let stack = state.stacks.get_by_name(n).unwrap();
            let id = stack.id();
            named.insert(id);
            println!(
                "{} {}",
                n.bold(),
                display_stack_contents(&stack, &state.stacks.secrets, &state.vtmf, cfg)
            );
        }
        if m.is_present("ALL") {
            for id in state.stacks.ids() {
                if !named.contains(id) {
                    let stack = state.stacks.get_by_id(&id).unwrap();
                    println!(
                        "{:16} {}",
                        id,
                        display_stack_contents(&stack, &state.stacks.secrets, &state.vtmf, cfg)
                    );
                }
            }
        }
    }

    Ok(())
}

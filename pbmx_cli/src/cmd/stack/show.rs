use crate::{stack_map::display_stack_contents, state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::crypto::vtmf::Stack;
use std::{collections::HashSet, iter::FromIterator};

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String).ok();

    let state = State::read(true)?;

    if let Some(id) = id {
        let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
        if state.stacks.is_name(&id) {
            print!("{} ", id.bold());
        }
        print_stack(m.is_present("VERBOSE"), &stack, &state, cfg);
    } else {
        let mut named = HashSet::new();
        let mut names: Vec<_> = state.stacks.names().collect();
        names.sort();
        for n in names {
            let stack = state.stacks.get_by_name(n).unwrap();
            let id = stack.id();
            named.insert(id);
            print!("{} ", n.bold());
            print_stack(m.is_present("VERBOSE"), &stack, &state, cfg);
        }
        if m.is_present("ALL") {
            for id in state.stacks.ids() {
                if !named.contains(id) {
                    let stack = state.stacks.get_by_id(&id).unwrap();
                    print!("{:16} ", id);
                    print_stack(m.is_present("VERBOSE"), &stack, &state, cfg);
                }
            }
        }
    }

    Ok(())
}

fn print_stack(verbose: bool, stack: &Stack, state: &State, cfg: &Config) {
    print!(
        "{}",
        display_stack_contents(
            stack,
            &state.stacks.secrets,
            &state.stacks.private_secrets,
            &state.vtmf,
            cfg
        )
    );
    if verbose {
        let empty = HashSet::new();
        let common: HashSet<_> = state.vtmf.fingerprints().collect();
        let common = stack
            .iter()
            .map(|m| {
                state
                    .stacks
                    .secrets
                    .get(m)
                    .map(|(_, fps)| HashSet::from_iter(fps.iter().cloned()))
                    .unwrap_or_else(|| empty.clone())
            })
            .fold(common, |acc, fps| acc.intersection(&fps).cloned().collect());
        print!(" $");
        let mut common: Vec<_> = common.into_iter().collect();
        common.sort();
        for fp in common.iter() {
            if let Some(n) = state.names.get(fp) {
                print!(" {}", n);
            } else {
                print!(" {:16}", fp);
            }
        }
        println!();
    } else {
        println!();
    }
}

use crate::{
    stack_map::{display_stack_contents, SecretMap},
    state::State,
    Config, Error, Result,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_curve::vtmf::{Stack, Vtmf};
use std::{collections::HashSet, iter::FromIterator};

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String).ok();

    let state = State::read(true)?;

    if let Some(id) = id {
        let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
        if state.stacks.is_name(&id) {
            print!("{} ", id.bold());
        }
        print_stack(
            m.is_present("VERBOSE"),
            &stack,
            &state.stacks.secrets,
            &state.vtmf,
            cfg,
        );
    } else {
        let mut named = HashSet::new();
        let mut names: Vec<_> = state.stacks.names().collect();
        names.sort();
        for n in names {
            let stack = state.stacks.get_by_name(n).unwrap();
            let id = stack.id();
            named.insert(id);
            print!("{} ", n.bold());
            print_stack(
                m.is_present("VERBOSE"),
                &stack,
                &state.stacks.secrets,
                &state.vtmf,
                cfg,
            );
        }
        if m.is_present("ALL") {
            for id in state.stacks.ids() {
                if !named.contains(id) {
                    let stack = state.stacks.get_by_id(&id).unwrap();
                    print!("{:16} ", id);
                    print_stack(
                        m.is_present("VERBOSE"),
                        &stack,
                        &state.stacks.secrets,
                        &state.vtmf,
                        cfg,
                    );
                }
            }
        }
    }

    Ok(())
}

fn print_stack(verbose: bool, stack: &Stack, secrets: &SecretMap, vtmf: &Vtmf, cfg: &Config) {
    print!("{}", display_stack_contents(stack, secrets, vtmf, cfg));
    if verbose {
        let empty = HashSet::new();
        let common: HashSet<_> = vtmf.fingerprints().collect();
        let common = stack
            .iter()
            .map(|m| {
                secrets
                    .get(m)
                    .map(|(_, fps)| HashSet::from_iter(fps.iter().cloned()))
                    .unwrap_or_else(|| empty.clone())
            })
            .fold(common, |acc, fps| acc.intersection(&fps).cloned().collect());
        print!(" $");
        let mut common: Vec<_> = common.into_iter().collect();
        common.sort();
        for fp in common.iter() {
            if let Some(n) = cfg.players.get(fp) {
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

use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;
use std::collections::HashSet;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let state = State::read(true)?;

    let mut named = HashSet::new();
    let mut names: Vec<_> = state.stacks.names().collect();
    names.sort();
    for n in names {
        let stack = state.stacks.get_by_name(n).unwrap();
        let id = stack.id();
        named.insert(id);
        println!(
            "{} {:4}\t{}",
            format!("{:16}", id).yellow(),
            stack.len(),
            n.bold()
        );
    }
    if m.is_present("ALL") {
        for id in state.stacks.ids() {
            if !named.contains(id) {
                let s = state.stacks.get_by_id(&id).unwrap();
                println!("{} {:4}", format!("{:16}", id).yellow(), s.len());
            }
        }
    }

    Ok(())
}

use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::Id;
use std::collections::HashSet;

pub fn list(m: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    let mut named = HashSet::new();
    for (n, s) in state.stacks.named_stacks() {
        let id = Id::of(s).unwrap();
        named.insert(id);
        println!("{} {}", format!("{:16}", id).yellow(), n.bold());
    }
    if m.is_present("ALL") {
        for id in state.stacks.ids() {
            if !named.contains(&id) {
                println!("{}", format!("{:16}", id).yellow());
            }
        }
    }

    state.save_payloads()?;
    Ok(())
}

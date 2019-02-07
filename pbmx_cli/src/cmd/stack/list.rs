use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use std::collections::HashSet;

pub fn list(m: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    let mut named = HashSet::new();
    for n in state.stacks.names() {
        let s = state.stacks.get_by_name(n).unwrap();
        let id = s.id();
        named.insert(id);
        print!(
            "{} {:4}\t{}",
            format!("{:16}", id).yellow(),
            s.len(),
            n.bold()
        );
        if !state.secrets.fingerprints(&id).is_empty() {
            print!("\t + {}{:16?}", "?".bold(), state.secrets.fingerprints(&id));
        }
        println!();
    }
    if m.is_present("ALL") {
        for id in state.stacks.ids() {
            if !named.contains(id) {
                let s = state.stacks.get_by_id(&id).unwrap();
                println!("{} {:4}", format!("{:16}", id).yellow(), s.len());
            }
        }
    }

    state.save_payloads()?;
    Ok(())
}

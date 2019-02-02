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
        println!(
            "{} {:4}\t{}",
            format!("{:16}", id).yellow(),
            s.len(),
            n.bold()
        );
    }
    if m.is_present("ALL") {
        for id in state.stacks.ids() {
            if !named.contains(&id) {
                let s = state.stacks.get_by_id(&id).unwrap();
                println!("{} {:4}", format!("{:16}", id).yellow(), s.len());
            }
        }
    }

    state.save_payloads()?;
    Ok(())
}

use crate::{error::Result, state::State};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_chain::Id;

pub fn list(m: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    if m.is_present("ALL") {
        unimplemented!()
    }
    for (n, s) in state.stacks.named_stacks() {
        println!(
            "{} {}",
            format!("{:16}", Id::of(s).unwrap()).yellow(),
            n.bold()
        );
    }

    state.save_payloads()?;
    Ok(())
}

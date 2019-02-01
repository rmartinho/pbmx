use crate::{error::Result, state::State};
use clap::ArgMatches;

pub fn reset(_: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    state.clear_payloads();
    state.save_payloads()?;

    Ok(())
}

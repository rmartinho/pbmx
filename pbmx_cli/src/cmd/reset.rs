use crate::{state::State, Config, Result};
use clap::ArgMatches;

pub fn reset(_: &ArgMatches, _: &Config) -> Result<()> {
    let mut state = State::read(false)?;

    state.clear_payloads();
    state.save_payloads()?;

    Ok(())
}

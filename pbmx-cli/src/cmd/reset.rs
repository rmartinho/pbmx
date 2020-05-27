use crate::{state::State, Config, Result};
use clap::ArgMatches;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let last = m.is_present("LAST");
    let index = value_t!(m, "INDEX", usize).ok();

    let mut state = State::read(false)?;

    if last {
        state.payloads.pop();
    } else if let Some(index) = index {
        state.payloads.remove(index);
    } else {
        state.clear_payloads();
    }

    state.save_payloads()?;

    Ok(())
}

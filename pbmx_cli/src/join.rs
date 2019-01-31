use crate::{error::Result, state::State};
use clap::ArgMatches;
use pbmx_chain::payload::Payload;

pub fn join(_: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    state
        .payloads
        .push(Payload::PublishKey(state.vtmf.public_key()));

    state.save_payloads()?;
    Ok(())
}

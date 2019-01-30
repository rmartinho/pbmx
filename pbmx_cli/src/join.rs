use crate::{error::Result, state::read_state};
use clap::ArgMatches;

pub fn join(_: &ArgMatches) -> Result<()> {
    let _state = dbg!(read_state());
    Ok(())
}

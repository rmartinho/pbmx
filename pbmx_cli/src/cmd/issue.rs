use crate::{
    constants::{BLOCKS_FOLDER_NAME, BLOCK_EXTENSION},
    file,
    state::State,
    Config, Result,
};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::serde::Message;
use std::path::PathBuf;

pub fn run(_: &ArgMatches, _: &Config) -> Result<()> {
    let mut state = State::read(false)?;

    let block = {
        let mut builder = state.base.chain.build_block();
        for payload in state.payloads.iter().cloned() {
            builder.add_payload(payload);
        }
        builder.build(&state.base.vtmf.private_key())
    };
    let id = block.id();

    let block_file = format!("{}.{}", id, BLOCK_EXTENSION);
    let mut path = PathBuf::from(BLOCKS_FOLDER_NAME);
    path.push(block_file);
    file::write_new(path, block.encode()?)?;
    println!("{} {:16}", " ^ Issue block".green().bold(), id);

    state.payloads.clear();
    state.save_payloads()?;
    Ok(())
}

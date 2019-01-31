use crate::{
    constants::{BLOCKS_FOLDER_NAME, BLOCK_EXTENSION},
    error::Result,
    file,
    state::State,
};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_serde::ToBase64;
use std::{
    io::{stdout, Write},
    path::PathBuf,
};

pub fn issue(_: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    print!("{}", " ^ Issue block ".green().bold());
    stdout().flush()?;
    let block = {
        let mut builder = state.chain.build_block();
        for payload in state.payloads.iter().cloned() {
            builder.add_payload(payload);
        }
        builder.build(&state.vtmf.private_key())
    };
    let id = block.id();

    let block_file = format!("{}.{}", id, BLOCK_EXTENSION);
    let mut path = PathBuf::from(BLOCKS_FOLDER_NAME);
    path.push(block_file);
    file::write_new(path, block.to_base64()?.as_bytes())?;
    println!("{}", id);

    state.payloads.clear();
    state.save_payloads()?;
    Ok(())
}

use crate::{
    error::{Error, Result},
    stack_map::display_stack_contents,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;

pub fn show(m: &ArgMatches) -> Result<()> {
    let state = State::read(true)?;

    let id = value_t!(m, "STACK", String)?;
    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
    if state.stacks.is_name(&id) {
        print!("{} ", id.bold());
    }
    println!(
        "{}",
        display_stack_contents(&stack, &state.stacks.secrets, &state.vtmf)
    );

    Ok(())
}

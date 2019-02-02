use crate::{
    error::{Error, Result},
    stacks::display_stack_contents,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;

pub fn show(m: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    let id = value_t!(m, "STACK", String)?;
    let (stack, name) = state.find_stack(&id).ok_or(Error::InvalidData)?;
    if name {
        print!("{} ", id.bold());
    }
    println!("{}", display_stack_contents(&stack, &state.vtmf));

    Ok(())
}

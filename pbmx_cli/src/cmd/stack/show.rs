use crate::{
    error::{Error, Result},
    stacks::display_stack_contents,
    state::State,
};
use clap::{value_t, ArgMatches};

pub fn show(m: &ArgMatches) -> Result<()> {
    let state = State::read()?;

    let id = value_t!(m, "STACK", String)?;
    let by_name = state
        .stacks
        .named_stacks()
        .find_map(|(n, s)| if n == id { Some(s) } else { None });
    let stack = if let Some(stack) = by_name {
        Some(stack)
    } else {
        state
            .stacks
            .ids()
            .find(|it| it.to_string().ends_with(&id))
            .and_then(|id| state.stacks.get_by_id(&id))
    };
    let stack = stack.ok_or(Error::InvalidData)?;
    println!("{}", display_stack_contents(&stack, &state.vtmf));

    Ok(())
}

use crate::{
    error::{Error, Result},
    indices::parse_indices,
    stacks::display_stack_contents,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use curve25519_dalek::scalar::Scalar;
use pbmx_chain::{payload::Payload, Id};

pub fn create(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = if m.is_present("HIDDEN") {
        unimplemented!()
    } else {
        let stack = values_t!(m, "TOKENS", String)
            .unwrap_or_else(|_| vec![])
            .iter()
            .map(|s| parse_indices(s).ok_or(Error::InvalidData))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .map(|i| state.vtmf.mask_open(&Scalar::from(i as u64)))
            .collect::<Vec<_>>();
        let id = Id::of(&stack).unwrap();
        println!(
            "{} {}",
            " + Open stack".green().bold(),
            display_stack_contents(&stack, &state.vtmf)
        );
        state.payloads.push(Payload::OpenStack(stack));
        id
    };
    let name = value_t!(m, "NAME", String).ok();
    if let Some(name) = name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id, name);
        state.payloads.push(Payload::NameStack(id, name));
    }

    state.save_payloads()?;
    Ok(())
}

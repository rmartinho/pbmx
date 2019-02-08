use crate::{
    error::{Error, Result},
    indices::parse_indices,
    stack_map::display_stack_contents,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use curve25519_dalek::scalar::Scalar;
use pbmx_chain::payload::Payload;
use pbmx_curve::vtmf::{Mask, Stack};
use std::collections::HashMap;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable};

const G: &RistrettoBasepointTable = &RISTRETTO_BASEPOINT_TABLE;

pub fn stack(m: &ArgMatches) -> Result<()> {
    let mut state = State::read(false)?;

    let stack: Stack = values_t!(m, "TOKENS", String)
        .unwrap_or_else(|_| vec![])
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .map(|i| Mask::open(G * &Scalar::from(i as u64)))
        .collect();
    let id = stack.id();
    println!(
        "{} {}",
        " + Open stack".green().bold(),
        display_stack_contents(&stack.clone(), &HashMap::new(), &state.vtmf)
    );
    state.payloads.push(Payload::OpenStack(stack));
    let name = value_t!(m, "NAME", String).ok();
    if let Some(name) = name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id, name);
        state.payloads.push(Payload::NameStack(id, name));
    }

    state.save_payloads()?;
    Ok(())
}

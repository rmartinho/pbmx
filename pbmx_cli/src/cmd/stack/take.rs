use crate::{
    error::{Error, Result},
    indices::parse_indices,
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::{payload::Payload, Id};
use pbmx_curve::perm::{Permutation, Shuffles};
use rand::{thread_rng, Rng};

pub fn take(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = value_t!(m, "SOURCE", String)?;
    let (stack, _) = state.find_stack(&id).ok_or(Error::InvalidData)?;
    let indices = values_t!(m, "INDICES", String)?;
    let indices: Vec<_> = indices
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(())
}

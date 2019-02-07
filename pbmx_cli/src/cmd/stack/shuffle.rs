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
use std::convert::TryFrom;

pub fn shuffle(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = value_t!(m, "STACK", String)?;
    let (stack, name) = state.find_stack(&id).ok_or(Error::InvalidData)?;

    let indices = values_t!(m, "TOKENS", String).ok();
    let perm = if let Some(indices) = indices {
        let v: Vec<_> = indices
            .iter()
            .map(|s| parse_indices(s).ok_or(Error::InvalidData))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Permutation::try_from(v).map_err(|_| Error::InvalidData)?
    } else {
        thread_rng().sample(&Shuffles(stack.len()))
    };
    let (s, proof) = state.vtmf.mask_shuffle(&stack.into(), &perm);

    let id1 = Id::of(&stack.to_vec()).unwrap();
    let id2 = Id::of(&s).unwrap();
    state.payloads.push(Payload::ShuffleStack(id1, s, proof));
    println!(
        "{} {:16} \u{224B} {:16}",
        " + Shuffle stack".green().bold(),
        id1,
        id2
    );
    if name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, id);
        state.payloads.push(Payload::NameStack(id2, id.to_string()));
    }

    state.save_payloads()?;
    Ok(())
}

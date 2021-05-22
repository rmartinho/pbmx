use crate::{state::State, Config, Error, Result};
use clap::ArgMatches;
use colored::Colorize;
use itertools::Itertools;
use pbmx_kit::{chain::Payload, crypto::perm::Permutation};
use rand::{thread_rng, Rng};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let ids = values_t!(m, "STACK", String)?;
    let n = value_t!(m, "N", usize).ok();

    let mut state = State::read(true)?;

    let stacks: Vec<_> = ids
        .iter()
        .map(|id| state.base.stacks.get_by_str(id).ok_or(Error::InvalidData))
        .collect::<Result<_>>()?;

    let (min, max) = stacks
        .iter()
        .map(|s| s.len())
        .minmax()
        .into_option()
        .ok_or(Error::InvalidData)?;
    if min != max {
        return Err(Error::InvalidData);
    }
    let len = min;

    let n = n.unwrap_or_else(|| thread_rng().gen_range(0..len));

    let mut payloads = Vec::new();
    let (shifts, secrets): (Vec<_>, Vec<_>) = stacks
        .iter()
        .zip(ids.iter())
        .map(|(stack, id)| {
            let (s, r, proof) = state.base.vtmf.mask_shift(&stack, n);

            let id1 = stack.id();
            let id2 = s.id();
            payloads.push(Payload::ShiftStack(id1, s.clone(), proof));
            println!(
                "{} {:16} \u{224B} {:16}",
                " + Cut stack".green().bold(),
                id1,
                id2
            );
            if state.base.stacks.is_name(&id) {
                println!("{} {:16} {}", " + Name stack".green().bold(), id2, id);
                payloads.push(Payload::NameStack(id2, id.to_string()));
            }
            (s, r)
        })
        .unzip();
    for (s, r) in shifts.iter().zip(secrets.iter()) {
        state.save_secrets(s, r.clone())?;
    }

    let entangle_proof = state.base.vtmf.prove_entanglement(
        stacks.iter().cloned(),
        shifts.iter(),
        &Permutation::shift(len, n),
        secrets.iter().map(|s| s.as_slice()),
    );
    let stack_ids = stacks.iter().map(|s| s.id()).collect();
    let shift_ids = shifts.iter().map(|s| s.id()).collect();

    state.payloads.extend(payloads.into_iter());
    if ids.len() > 1 {
        println!(
            "{} {:16?} \u{224B} {:16?}",
            " + Entangled".green().bold(),
            stack_ids,
            shift_ids
        );
        state.payloads.push(Payload::ProveEntanglement(
            stack_ids,
            shift_ids,
            entangle_proof,
        ));
    }

    state.save_payloads()?;
    Ok(())
}

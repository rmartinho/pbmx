use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use rand::{thread_rng, Rng};

pub fn cut(m: &ArgMatches, _: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String)?;
    let n = value_t!(m, "N", usize);

    let mut state = State::read(true)?;

    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;
    let n = n.unwrap_or_else(|_| thread_rng().gen_range(0, stack.len()));

    let (s, proof) = state.vtmf.mask_shift(&stack, n);

    let id1 = stack.id();
    let id2 = s.id();
    state.payloads.push(Payload::ShiftStack(id1, s, proof));
    println!(
        "{} {:16} \u{224B} {:16}",
        " + Cut stack".green().bold(),
        id1,
        id2
    );
    if state.stacks.is_name(&id) {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, id);
        state.payloads.push(Payload::NameStack(id2, id.to_string()));
    }

    state.save_payloads()?;
    Ok(())
}

use crate::{
    error::{Error, Result},
    state::State,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::vtmf::Stack;

pub fn mask(m: &ArgMatches) -> Result<()> {
    let mut state = State::read()?;

    let id = value_t!(m, "STACK", String)?;
    let (e, name) = state.find_stack(&id).ok_or(Error::InvalidData)?;

    let (s, p): (Stack, Vec<_>) = e.stack.iter().map(|m| state.vtmf.remask(m)).unzip();

    let id1 = e.stack.id();
    let id2 = s.id();
    state.payloads.push(Payload::MaskStack(id1, s, p));
    println!(
        "{} {:16} \u{21AC} {:16}",
        " + Mask stack".green().bold(),
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

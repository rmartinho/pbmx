use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_chain::payload::Payload;
use pbmx_curve::vtmf::Stack;

pub fn pile(m: &ArgMatches, _: &Config) -> Result<()> {
    let in_ids = values_t!(m, "STACKS", String)?;
    let name = value_t!(m, "TARGET", String).ok();
    let remove = m.is_present("REMOVE");

    let mut state = State::read(true)?;

    let stacks: Vec<_> = in_ids
        .iter()
        .map(|id| {
            state
                .stacks
                .get_by_str(&id)
                .ok_or(Error::InvalidData)
                .map(|s| s.clone())
        })
        .collect::<Result<_>>()?;
    let ids: Vec<_> = stacks.iter().map(Stack::id).collect();

    let tokens: Stack = stacks.into_iter().flat_map(|s| s.into_iter()).collect();

    if remove {
        let empty = Stack::default();
        let id3 = empty.id();
        for id in in_ids.iter() {
            if state.stacks.is_name(id) {
                println!("{} []", " + Open stack".green().bold());
                state.payloads.push(Payload::OpenStack(empty.clone()));
                println!("{} {:16} {}", " + Name stack".green().bold(), id3, id);
                state.payloads.push(Payload::NameStack(id3, id.clone()));
            }
        }
    }
    let id2 = tokens.id();
    println!(
        "{} {:?} \u{21A3} {:16}",
        " + Pile stacks".green().bold(),
        in_ids,
        id2
    );
    state.payloads.push(Payload::PileStacks(ids, tokens));
    if let Some(name) = name {
        println!("{} {:16} {}", " + Name stack".green().bold(), id2, name);
        state.payloads.push(Payload::NameStack(id2, name));
    }

    state.save_payloads()?;
    Ok(())
}

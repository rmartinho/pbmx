use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::{chain::Payload, crypto::vtmf::Stack};
use rand::{thread_rng, Rng};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let ids = value_t!(m, "SOURCE", String)?;
    let idt = value_t!(m, "TARGET", String)?;
    let pos = value_t!(m, "INDEX", usize).ok();
    let remove = !m.is_present("CLONE");

    let mut state = State::read(true)?;

    let s1 = state
        .base
        .stacks
        .get_by_str(&ids)
        .ok_or(Error::InvalidData)?;
    let s2 = state
        .base
        .stacks
        .get_by_str(&idt)
        .ok_or(Error::InvalidData)?;
    let pos = pos.unwrap_or_else(|| thread_rng().gen_range(0, s1.len() + 1));
    if pos > s2.len() + 1 {
        return Err(Error::InvalidData);
    }

    let (s3, r, proof) = state.base.vtmf.mask_insert(&s1, &s2, pos);
    state.save_secrets(&s3, r)?;

    let id1 = s1.id();
    let id2 = s2.id();
    let id3 = s3.id();
    state
        .payloads
        .push(Payload::InsertStack(id1, id2, s3, proof));
    println!(
        "{} {:16} {:16} {:16}",
        " + Insert stack".green().bold(),
        id1,
        id2,
        id3
    );
    if state.base.stacks.is_name(&idt) {
        println!("{} {:16} {}", " + Name stack".green().bold(), id3, idt);
        state
            .payloads
            .push(Payload::NameStack(id3, idt.to_string()));
    }

    if remove && state.base.stacks.is_name(&ids) {
        let empty = Stack::default();
        let eid = empty.id();
        println!("{} []", " + Open stack".green().bold());
        state.payloads.push(Payload::OpenStack(empty));
        println!("{} {:16} {}", " + Name stack".green().bold(), eid, ids);
        state
            .payloads
            .push(Payload::NameStack(eid, ids.to_string()));
    }

    state.save_payloads()?;
    Ok(())
}

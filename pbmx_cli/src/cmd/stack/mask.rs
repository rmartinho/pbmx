use crate::{state::State, Config, Error, Result};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::{chain::Payload, crypto::vtmf::Stack};
use std::iter;

trait IteratorEx: Iterator + Sized {
    fn unzip3<A, B, C, FromA, FromB, FromC>(self) -> (FromA, FromB, FromC)
    where
        FromA: Default + Extend<A>,
        FromB: Default + Extend<B>,
        FromC: Default + Extend<C>,
        Self: Iterator<Item = (A, B, C)>,
    {
        let mut r_a = FromA::default();
        let mut r_b = FromB::default();
        let mut r_c = FromC::default();

        for (a, b, c) in self {
            r_a.extend(iter::once(a));
            r_b.extend(iter::once(b));
            r_c.extend(iter::once(c));
        }

        (r_a, r_b, r_c)
    }
}

impl<T: Iterator> IteratorEx for T {}

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let id = value_t!(m, "STACK", String)?;

    let mut state = State::read(true)?;

    let stack = state.stacks.get_by_str(&id).ok_or(Error::InvalidData)?;

    let (s, r, p): (Stack, Vec<_>, Vec<_>) = stack.iter().map(|m| state.vtmf.remask(m)).unzip3();
    state.save_secrets(&s, r)?;

    let id1 = stack.id();
    let id2 = s.id();
    state.payloads.push(Payload::MaskStack(id1, s, p));
    println!(
        "{} {:16} \u{21AC} {:16}",
        " + Mask stack".green().bold(),
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

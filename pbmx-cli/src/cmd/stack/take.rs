use crate::{
    indices::{display_indices, parse_indices},
    state::State,
    Config, Error, Result,
};
use clap::{value_t, ArgMatches};
use colored::Colorize;
use pbmx_kit::{chain::Payload, crypto::vtmf::Stack};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let id = value_t!(m, "SOURCE", String)?;
    let indices = values_t!(m, "INDICES", String)?;
    let target = value_t!(m, "TARGET", String).ok();
    let over = value_t!(m, "OVER", String).ok();
    let under = value_t!(m, "UNDER", String).ok();
    let remove = !m.is_present("CLONE");

    let mut state = State::read(true)?;

    let stack = state
        .base
        .stacks
        .get_by_str(&id)
        .ok_or(Error::InvalidData)?
        .clone();
    let indices: Vec<_> = indices
        .iter()
        .map(|s| parse_indices(s).ok_or(Error::InvalidData))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    if remove && state.base.stacks.is_name(&id) {
        let rev_indices: Vec<_> = (0..stack.len()).filter(|i| !indices.contains(&i)).collect();
        take(&stack, rev_indices, Some(id), Stacking::Replace, &mut state)?;
    }
    let stacking = if let Some(over) = over {
        Stacking::Over(over)
    } else if let Some(under) = under {
        Stacking::Under(under)
    } else {
        Stacking::Replace
    };
    take(&stack, indices, target, stacking, &mut state)?;

    state.save_payloads()?;
    Ok(())
}

enum Stacking {
    Replace,
    Over(String),
    Under(String),
}

fn take(
    stack: &Stack,
    indices: Vec<usize>,
    target: Option<String>,
    stacking: Stacking,
    state: &mut State,
) -> Result<()> {
    let tokens: Stack = stack
        .iter()
        .enumerate()
        .filter_map(|(i, m)| if indices.contains(&i) { Some(*m) } else { None })
        .collect();

    let id1 = stack.id();
    let id2 = tokens.id();
    println!(
        "{} {:16}{} \u{219B} {:16}",
        " + Take tokens".green().bold(),
        id1,
        display_indices(&indices),
        id2
    );
    state.payloads.push(Payload::TakeStack(id1, indices, id2));
    let (name, result) = match stacking {
        Stacking::Over(over) => {
            let o = state
                .base
                .stacks
                .get_by_str(&over)
                .ok_or(Error::InvalidData)?
                .clone();
            let pile: Stack = tokens.iter().chain(o.iter()).cloned().collect();
            let ids = vec![o.id(), id2];
            println!(
                "{} {:16?} \u{21A3} {:16}",
                " + Pile stacks".green().bold(),
                ids,
                pile.id()
            );
            state.payloads.push(Payload::PileStacks(ids, pile.id()));
            (Some(over), pile)
        }
        Stacking::Under(under) => {
            let u = state
                .base
                .stacks
                .get_by_str(&under)
                .ok_or(Error::InvalidData)?
                .clone();
            let pile: Stack = u.iter().chain(tokens.iter()).cloned().collect();
            let ids = vec![id2, u.id()];
            println!(
                "{} {:16?} \u{21A3} {:16}",
                " + Pile stacks".green().bold(),
                ids,
                pile.id()
            );
            state.payloads.push(Payload::PileStacks(ids, pile.id()));
            (Some(under), pile)
        }
        Stacking::Replace => (target, tokens),
    };
    let id3 = result.id();
    if let Some(target) = name {
        let name_change = state
            .base
            .stacks
            .get_by_name(&target)
            .map(|s| s.id() != id3)
            .unwrap_or(true);
        if name_change {
            println!("{} {:16} {}", " + Name stack".green().bold(), id3, target);
            state.payloads.push(Payload::NameStack(id3, target));
        }
    }

    Ok(())
}

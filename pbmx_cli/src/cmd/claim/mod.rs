use crate::{stack_map::unmask_stack, state::State, Config, Error, Result};
use clap::ArgMatches;
use pbmx_kit::crypto::{map, vtmf::Stack};

pub mod disjoint;
pub mod list;
pub mod subset;
pub mod superset;
pub mod verify;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    match m.subcommand() {
        ("list", Some(sub_m)) => list::run(sub_m, cfg),
        ("verify", Some(sub_m)) => verify::run(sub_m, cfg),
        ("subset", Some(sub_m)) => subset::run(sub_m, cfg),
        ("superset", Some(sub_m)) => superset::run(sub_m, cfg),
        ("disjoint", Some(sub_m)) => disjoint::run(sub_m, cfg),
        _ => Err(Error::InvalidSubcommand),
    }
}

fn full_unmask_stack<'a>(s: &Stack, state: &'a State) -> Result<impl Iterator<Item = u64> + 'a> {
    Ok(unmask_stack(
        s,
        &state.base.stacks.secrets(),
        &state.base.stacks.private_secrets(),
        &state.base.vtmf,
        &state.base.vtmf.private_key().fingerprint(),
    )
    .ok_or(Error::InvalidData)?
    .into_iter()
    .map(move |c| map::from_curve(&state.base.vtmf.unmask_open(&c))))
}

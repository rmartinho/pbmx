use crate::{Config, Error, Result};
use clap::ArgMatches;

pub mod list;
pub mod subset;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    match m.subcommand() {
        ("list", Some(sub_m)) => list::run(sub_m, cfg),
        ("subset", Some(sub_m)) => subset::run(sub_m, cfg),
        ("superset", Some(sub_m)) => subset::run(sub_m, cfg),
        ("disjoint", Some(sub_m)) => subset::run(sub_m, cfg),
        _ => Err(Error::InvalidSubcommand),
    }
}

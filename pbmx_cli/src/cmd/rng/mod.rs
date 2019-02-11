use crate::{Config, Error, Result};
use clap::ArgMatches;

pub mod entropy;
pub mod get;
pub mod list;
pub mod new;
pub mod reveal;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    match m.subcommand() {
        ("new", Some(sub_m)) => new::run(sub_m, cfg),
        ("list", Some(sub_m)) => list::run(sub_m, cfg),
        ("entropy", Some(sub_m)) => entropy::run(sub_m, cfg),
        ("reveal", Some(sub_m)) => reveal::run(sub_m, cfg),
        ("get", Some(sub_m)) => get::run(sub_m, cfg),
        _ => Err(Error::InvalidSubcommand),
    }
}

use crate::{Config, Error, Result};
use clap::ArgMatches;

pub mod cut;
pub mod insert;
pub mod list;
pub mod mask;
pub mod name;
pub mod new;
pub mod pile;
pub mod reveal;
pub mod show;
pub mod shuffle;
pub mod take;

pub fn run(m: &ArgMatches, cfg: &Config) -> Result<()> {
    match m.subcommand() {
        ("new", Some(sub_m)) => new::run(sub_m, cfg),
        ("list", Some(sub_m)) => list::run(sub_m, cfg),
        ("show", Some(sub_m)) => show::run(sub_m, cfg),
        ("name", Some(sub_m)) => name::run(sub_m, cfg),
        ("reveal", Some(sub_m)) => reveal::run(sub_m, cfg),
        ("mask", Some(sub_m)) => mask::run(sub_m, cfg),
        ("shuffle", Some(sub_m)) => shuffle::run(sub_m, cfg),
        ("cut", Some(sub_m)) => cut::run(sub_m, cfg),
        ("take", Some(sub_m)) => take::run(sub_m, cfg),
        ("pile", Some(sub_m)) => pile::run(sub_m, cfg),
        ("insert", Some(sub_m)) => insert::run(sub_m, cfg),
        _ => Err(Error::InvalidSubcommand),
    }
}

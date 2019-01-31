use crate::error::{Error, Result};
use clap::ArgMatches;

mod new;
use self::new::new;
mod add;
use self::add::add;
mod gen;
use self::gen::gen;

pub fn random(m: &ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("new", Some(sub_m)) => new(sub_m),
        ("add", Some(sub_m)) => add(sub_m),
        ("gen", Some(sub_m)) => gen(sub_m),
        _ => Err(Error::InvalidSubcommand),
    }
}


use crate::error::{Error, Result};
use clap::ArgMatches;

mod create;
use self::create::create;
mod list;
use self::list::list;
mod show;
use self::show::show;
mod mask;
use self::mask::mask;
mod shuffle;
use self::shuffle::shuffle;
mod cut;
use self::cut::cut;
mod take;
use self::take::take;
mod pile;
use self::pile::pile;
mod reveal;
use self::reveal::reveal;

pub fn stack(m: &ArgMatches) -> Result<()> {
    match m.subcommand() {
        ("create", Some(sub_m)) => create(sub_m),
        ("list", Some(sub_m)) => list(sub_m),
        ("show", Some(sub_m)) => show(sub_m),
        ("mask", Some(sub_m)) => mask(sub_m),
        ("shuffle", Some(sub_m)) => shuffle(sub_m),
        ("cut", Some(sub_m)) => cut(sub_m),
        ("take", Some(sub_m)) => take(sub_m),
        ("pile", Some(sub_m)) => pile(sub_m),
        ("reveal", Some(sub_m)) => reveal(sub_m),
        _ => Err(Error::InvalidSubcommand),
    }
}

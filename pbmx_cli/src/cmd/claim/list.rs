use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;
use pbmx_kit::{chain::Payload::*, state::Claim};

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let state = State::read(true)?;

    fn all(_: &Claim) -> bool {
        true
    }
    fn verified(c: &Claim) -> bool {
        c.is_verified()
    }
    fn pending(c: &Claim) -> bool {
        !c.is_verified()
    }

    let filter = if m.is_present("PENDING") {
        pending
    } else if m.is_present("VERIFIED") {
        verified
    } else {
        all
    };
    for (_, claim) in state.base.claims.iter() {
        if filter(claim) {
            println!(
                " {} {}",
                if claim.is_verified() {
                    "\u{2714}".green()
                } else {
                    "\u{2718}".yellow()
                },
                match claim.payload() {
                    ProveSubset(id1, id2, ..) => format!("{:8?} \u{2286} {:8?}", id1, id2),
                    ProveSuperset(id1, id2, ..) => format!("{:8?} \u{2287} {:8?}", id1, id2),
                    ProveDisjoint(id1, id2, ..) => format!("{:8?} \u{2260} {:8?}", id1, id2),
                    _ => "unknown claim".to_string(),
                }
            );
        }
    }

    Ok(())
}

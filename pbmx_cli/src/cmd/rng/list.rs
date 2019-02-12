use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;

pub fn run(m: &ArgMatches, _: &Config) -> Result<()> {
    let state = State::read(true)?;

    let keys = state.rngs.iter().map(|(k, v)| (k, v.is_revealed()));

    for k in keys.clone().filter(|x| !x.1).map(|x| x.0) {
        let rng = &state.rngs[k];
        println!("{} < {}", k.yellow(), rng.bound());
    }

    if m.is_present("ALL") {
        for k in keys.filter(|x| x.1).map(|x| x.0) {
            let rng = &state.rngs[k];
            println!(
                "{} < {} = {}",
                k.yellow(),
                rng.bound(),
                rng.gen(&state.vtmf)
            );
        }
    }

    Ok(())
}

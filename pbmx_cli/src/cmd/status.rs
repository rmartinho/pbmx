use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;

pub fn run(_: &ArgMatches, _: &Config) -> Result<()> {
    let state = State::read(false)?;

    println!("   {}", "Chain".blue().bold());
    println!(
        "    {}  {}",
        "Blocks".blue().bold(),
        state.base.chain.count()
    );
    if !state.base.chain.is_empty() {
        print!("    {}  ", "Heads".blue().bold());
        for head in state.base.chain.heads().iter() {
            print!(" {:16}", head);
        }
        println!();
        print!("    {}  ", "Roots".blue().bold());
        for root in state.base.chain.roots().iter() {
            print!(" {:16}", root);
        }
        println!();
    }

    println!("   {}", "Keys".blue().bold());
    println!(
        "    {} {:16}",
        "Private".blue().bold(),
        state.base.vtmf.private_key().fingerprint()
    );
    println!(
        "    {}  {:16}",
        "Shared".blue().bold(),
        state.base.vtmf.shared_key().fingerprint()
    );

    if !state.base.stacks.is_empty() {
        println!(
            "   {} {} ({})",
            "Stacks".blue().bold(),
            state.base.stacks.names().count(),
            state.base.stacks.len()
        );
    }

    if !state.base.rngs.is_empty() {
        println!("   {} {}", "Rngs".blue().bold(), state.base.rngs.len());
    }

    if !state.payloads.is_empty() {
        println!("   {}", "Next block".blue().bold());
        for payload in state.payloads.iter() {
            println!("    {}", payload.display_short());
        }
    }

    Ok(())
}

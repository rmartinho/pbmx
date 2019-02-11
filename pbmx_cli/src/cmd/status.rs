use crate::{state::State, Config, Result};
use clap::ArgMatches;
use colored::Colorize;

pub fn run(_: &ArgMatches, _: &Config) -> Result<()> {
    let state = State::read(false)?;

    println!("   {}", "Chain".blue().bold());
    println!("    {}  {}", "Blocks".blue().bold(), state.chain.count());
    if !state.chain.is_empty() {
        print!("    {}  ", "Heads".blue().bold());
        for head in state.chain.heads().iter() {
            print!(" {:16}", head);
        }
        println!();
        print!("    {}  ", "Roots".blue().bold());
        for root in state.chain.roots().iter() {
            print!(" {:16}", root);
        }
        println!();
    }

    println!("   {}", "Keys".blue().bold());
    println!(
        "    {} {:16}",
        "Private".blue().bold(),
        state.vtmf.private_key().fingerprint()
    );
    println!(
        "    {}  {:16}",
        "Shared".blue().bold(),
        state.vtmf.shared_key().fingerprint()
    );

    if !state.stacks.is_empty() {
        println!(
            "   {} {} ({})",
            "Stacks".blue().bold(),
            state.stacks.names().count(),
            state.stacks.len()
        );
    }

    if !state.rngs.is_empty() {
        println!("   {} {}", "Rngs".blue().bold(), state.rngs.len());
    }

    if !state.payloads.is_empty() {
        println!("   {}", "Next block".blue().bold());
        for payload in state.payloads.iter() {
            println!("    {}", payload.display_short());
        }
    }

    Ok(())
}

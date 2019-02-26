#![feature(option_xor)]
#![deny(clippy::correctness)]
#![allow(dead_code)]

#[macro_use]
extern crate clap;

#[macro_use]
extern crate serde_derive;

mod config;
use config::Config;
mod constants;
mod error;
use error::{Error, Result};
mod file;
mod indices;
mod random;
mod stack_map;
mod state;

mod cmd;
use cmd::{init, issue, join, log, message, reset, rng, stack, status};

fn main() {
    let cfg = Config::read().unwrap();

    let matches = clap_app!(pbmx =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@setting DeriveDisplayOrder)
        (@setting ColoredHelp)
        (@setting SubcommandRequiredElseHelp)
        (@setting VersionlessSubcommands)
        (@subcommand init =>
            (about: "Initializes a new game folder")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg PATH: +required "The folder to hold game data")
        )
        (@subcommand reset =>
            (about: "Resets the current block")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg LAST: -l --last conflicts_with[INDEX] "Undoes only the latest payload")
            (@arg INDEX: -p --payload +takes_value +hidden conflicts_with[LAST] "Undoes only the payload with the given index")
        )
        (@subcommand issue =>
            (about: "Issues the current block")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
        )
        (@subcommand join =>
            (about: "Joins the game")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
        )
        (@subcommand status =>
            (about: "Displays the game status")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
        )
        (@subcommand log =>
            (about: "Displays the game log")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
        )
        (@subcommand message =>
            (about: "Adds a message to the current block")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@group data +required =>
                (@arg MESSAGE: "The message")
                (@arg BASE64: -b --base64 +takes_value "Use a binary message given in base64")
                (@arg FILE: -f --file +takes_value "Use the contents of the file as the message")
            )
        )
        (@subcommand stack =>
            (about: "Stack manipulation")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@setting VersionlessSubcommands)
            (@subcommand new =>
                (about: "Creates a new stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg TOKENS: +multiple +use_delimiter "The tokens in the stack")
                (@arg NAME: -n --name +takes_value "Sets the name of the stack")
            )
            (@subcommand list =>
                (about: "Lists existing stacks")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg ALL: -a --all "Also includes unnamed stacks")
            )
            (@subcommand show =>
                (about: "Shows a stack's details")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: "The name or identifier of the stack (shows all named stacks if none given)")
                (@arg ALL: -a --all "Include unnamed stacks")
                (@arg VERBOSE: -v --verbose "Includes more details, e.g. encrypted data")
            )
            (@subcommand reveal =>
                (about: "Reveals the secret share of a stack to others")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
            )
            (@subcommand name =>
                (about: "Names a stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg ID: +required "The stack ID")
                (@arg NAME: +required "The name of the stack")
            )
            (@subcommand mask =>
                (about: "Remasks a stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
            )
            (@subcommand shuffle =>
                (about: "Shuffles a stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg ORDER: -o --order [INDICES] +multiple +use_delimiter "Chooses a specific order instead of randomizing")
            )
            (@subcommand cut =>
                (about: "Cuts a stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg N: -n +takes_value "Chooses a specific cut size instead of randomizing")
            )
            (@subcommand take =>
                (about: "Takes some tokens from an existing stack into another")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg SOURCE: +required "The name or identifier of the source stack")
                (@arg INDICES: +required +multiple +use_delimiter "The indices of the tokens to remove")
                (@arg TARGET: -t --to +takes_value conflicts_with[OVER] conflicts_with[UNDER] "The name or identifier for the target stack")
                (@arg OVER: -o --over +takes_value conflicts_with[UNDER] conflicts_with[TARGET] "Piles the tokens on top of this stack")
                (@arg UNDER: -u --under +takes_value conflicts_with[OVER] conflicts_with[TARGET] "Piles the tokens at the bottom of this stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stack (default)")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack")
            )
            (@subcommand pile =>
                (about: "Piles several stacks together")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACKS: +required +multiple "The name or identifier of the source stacks, from top to bottom")
                (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stacks (default)")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack")
            )
            (@subcommand insert =>
                (about: "Insert a stack into another")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg SOURCE: +required "The name or identifier of the source stack")
                (@arg TARGET: +required "The name or identifier for the target stack")
                (@arg INDEX: "The position for insertion in the target stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stacks (default)")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack")
            )
        )
        (@subcommand rng =>
            (about: "Random number generation")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@setting VersionlessSubcommands)
            (@subcommand new =>
                (about: "Initializes a new generator")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg NAME: +required "The name of the generator")
                (@arg BOUND: +required "The upper bound of the number to be generated")
            )
            (@subcommand list =>
                (about: "Lists existing generators")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg ALL: -a --all "Also includes completed generators")
            )
            (@subcommand entropy =>
                (about: "Adds an entropy share to a generator")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg NAME: +required "The name of the generator")
            )
            (@subcommand reveal =>
                (about: "Reveals the secret share of a generator to others")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg NAME: +required "The name of the generator")
            )
            (@subcommand get =>
                (about: "Gets the generator random number from a generator")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg NAME: +required "The name of the generator")
            )
        )
    )
    .get_matches();

    match matches.subcommand() {
        ("init", Some(sub_m)) => init::run(sub_m, &cfg),
        ("reset", Some(sub_m)) => reset::run(sub_m, &cfg),
        ("issue", Some(sub_m)) => issue::run(sub_m, &cfg),
        ("join", Some(sub_m)) => join::run(sub_m, &cfg),
        ("status", Some(sub_m)) => status::run(sub_m, &cfg),
        ("log", Some(sub_m)) => log::run(sub_m, &cfg),
        ("message", Some(sub_m)) => message::run(sub_m, &cfg),
        ("stack", Some(sub_m)) => stack::run(sub_m, &cfg),
        ("rng", Some(sub_m)) => rng::run(sub_m, &cfg),
        _ => Err(Error::InvalidSubcommand),
    }
    .unwrap_or_else(|e| e.exit());
}

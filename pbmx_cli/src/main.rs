#![feature(try_from)]
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
mod stack_map;
mod state;

mod cmd;
use cmd::{
    cut::cut, init::init, issue::issue, join::join, list::list, log::log, mask::mask,
    message::message, pile::pile, reset::reset, reveal::reveal, show::show, shuffle::shuffle,
    stack::stack, status::status, take::take,
};

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
        )
        (@subcommand issue =>
            (about: "Issues the current block")
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
            (@arg STACK: +required "The name or identifier of the stack")
            (@arg VERBOSE: -v --verbose "Includes more details, e.g. encrypted data")
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
            (about: "Cuts a stack (unimplemented)")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg STACK: +required "The name or identifier of the stack")
            (@arg N: -n +takes_value "Chooses a specific cut size instead of randomizing")
        )
        (@subcommand take =>
            (about: "Takes some tokens from an existing stack into another (unimplemented)")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg SOURCE: +required "The name or identifier of the source stack")
            (@arg INDICES: +required +multiple +use_delimiter "The indices of the tokens to remove")
            (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
            (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stack (unimplemented)")
            (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
        )
        (@subcommand pile =>
            (about: "Piles several stacks together (unimplemented)")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg STACKS: +required +multiple "The name or identifier of the source stacks, from top to bottom")
            (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
            (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stacks (unimplemented)")
            (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
        )
        (@subcommand reveal =>
            (about: "Reveals the secret share of a stack to others")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@arg STACK: +required "The name or identifier of the stack")
        )
    )
    .get_matches();

    match matches.subcommand() {
        ("init", Some(sub_m)) => init(sub_m, &cfg),
        ("reset", Some(sub_m)) => reset(sub_m, &cfg),
        ("issue", Some(sub_m)) => issue(sub_m, &cfg),
        ("join", Some(sub_m)) => join(sub_m, &cfg),
        ("status", Some(sub_m)) => status(sub_m, &cfg),
        ("log", Some(sub_m)) => log(sub_m, &cfg),
        ("message", Some(sub_m)) => message(sub_m, &cfg),
        ("stack", Some(sub_m)) => stack(sub_m, &cfg),
        ("list", Some(sub_m)) => list(sub_m, &cfg),
        ("show", Some(sub_m)) => show(sub_m, &cfg),
        ("mask", Some(sub_m)) => mask(sub_m, &cfg),
        ("shuffle", Some(sub_m)) => shuffle(sub_m, &cfg),
        ("cut", Some(sub_m)) => cut(sub_m, &cfg),
        ("take", Some(sub_m)) => take(sub_m, &cfg),
        ("pile", Some(sub_m)) => pile(sub_m, &cfg),
        ("reveal", Some(sub_m)) => reveal(sub_m, &cfg),
        _ => Err(Error::InvalidSubcommand),
    }
    .unwrap_or_else(|e| e.exit());
}

#![deny(clippy::correctness)]
// TODO REMOVE
#![allow(dead_code)]

#[macro_use]
extern crate clap;

mod constants;
mod error;
use self::error::Error;
mod file;
mod indices;
mod secrets;
mod stacks;
mod state;

mod cmd;
use cmd::{
    init::init, issue::issue, join::join, log::log, message::message, reset::reset, stack::stack,
    status::status,
};

fn main() {
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
            (about: "Manipulates stacks")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@subcommand create =>
                (about: "Creates a new stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg TOKENS: +multiple +use_delimiter "The tokens in the stack")
                (@arg NAME: -n --name +takes_value "Sets the name of the stack")
                (@arg HIDDEN: -H --hidden conflicts_with[OPEN] "Makes the stack contents hidden from others (unimplemented)")
                (@arg OPEN: -O --open conflicts_with[HIDDEN] "Makes the stack contents open to others (default)")
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
                (about: "Remasks a stack (unimplemented)")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
            )
            (@subcommand shuffle =>
                (about: "Shuffles a stack (unimplemented)")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg ORDER: -o --order <INDICES> +multiple +use_delimiter "Chooses a specific order instead of randomizing")
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
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stack")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
            )
            (@subcommand pile =>
                (about: "Piles several stacks together (unimplemented)")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACKS: +required +multiple "The name or identifier of the source stacks, from top to bottom")
                (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stacks")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
            )
            (@subcommand reveal =>
                (about: "Reveals the secret share of a stack to others (unimplemented)")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +required "The name or identifier of the stack")
            )
        )
        (@subcommand reset =>
            (about: "Resets the current block")
        )
        (@subcommand issue =>
            (about: "Issues the current block")
        )
    )
    .get_matches();

    match matches.subcommand() {
        ("init", Some(sub_m)) => init(sub_m),
        ("join", Some(sub_m)) => join(sub_m),
        ("status", Some(sub_m)) => status(sub_m),
        ("log", Some(sub_m)) => log(sub_m),
        ("message", Some(sub_m)) => message(sub_m),
        ("stack", Some(sub_m)) => stack(sub_m),
        ("reset", Some(sub_m)) => reset(sub_m),
        ("issue", Some(sub_m)) => issue(sub_m),
        _ => Err(Error::InvalidSubcommand),
    }
    .unwrap_or_else(|e| e.exit());
}

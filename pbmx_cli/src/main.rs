#![deny(clippy::correctness)]
#![allow(dead_code)]

#[macro_use]
extern crate clap;

#[macro_use]
extern crate nom;

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
use cmd::{bin, claim, init, issue, join, log, message, reset, rng, stack, status};

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
            (@arg PATH: "The folder to hold game data (default: current folder)")
        )
        (@subcommand reset =>
            (about: "Resets the current block")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@group which =>
                (@arg LAST: -l --last "Undoes only the latest payload")
                (@arg INDEX: -p --payload +takes_value +hidden "Undoes only the payload with the given index (experimental)")
            )
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
            (@arg NAME: +required "Your player name")
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
                (@arg FILE: -f --file +takes_value "Use the contents of the file as the message")
            )
        )
        (@subcommand bin =>
            (about: "Adds arbitrary binary data to the current block")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@group data +required =>
                (@arg BASE64: "The data in base64")
                (@arg FILE: -f --file +takes_value "Use the contents of the file as data")
            )
        )
        (@subcommand stack =>
            (about: "Stack manipulation")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@setting VersionlessSubcommands)
            (@setting DisableHelpSubcommand)
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
                (@arg STACK: +multiple +required "The name or identifier of the stack")
                (@arg ORDER: -o --order +takes_value "Chooses a specific order instead of randomizing")
            )
            (@subcommand cut =>
                (about: "Cuts a stack")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK: +multiple +required "The name or identifier of the stack")
                (@arg N: -n +takes_value "Chooses a specific cut size instead of randomizing")
            )
            (@subcommand take =>
                (about: "Takes some tokens from an existing stack into another")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg SOURCE: +required "The name or identifier of the source stack")
                (@arg INDICES: +required +multiple +use_delimiter "The indices of the tokens to remove")
                (@group location =>
                    (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                    (@arg OVER: -o --over +takes_value "Piles the tokens on top of this stack")
                    (@arg UNDER: -u --under +takes_value "Piles the tokens at the bottom of this stack")
                )
                (@group mode =>
                    (@arg REMOVE: -r --remove "Remove the tokens from the source stack (default)")
                    (@arg CLONE: -c --clone "Clones the tokens into the target stack")
                )
            )
            (@subcommand pile =>
                (about: "Piles several stacks together")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACKS: +required +multiple "The name or identifier of the source stacks, from top to bottom")
                (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                (@group mode =>
                    (@arg REMOVE: -r --remove "Remove the tokens from the source stacks (default)")
                    (@arg CLONE: -c --clone "Clones the tokens into the target stack")
                )
            )
        )
        (@subcommand claim =>
            (about: "Verifiable claims")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@setting VersionlessSubcommands)
            (@setting DisableHelpSubcommand)
            (@subcommand list =>
                (about: "Lists existing claims")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@group filter =>
                    (@arg ALL: -a --all "List all claims (default)")
                    (@arg PENDING: -p --pending "List only claims pending verification")
                    (@arg VERIFIED: -v --verified "List only fully verified claims")
                )
            )
            (@subcommand verify =>
                (about: "Takes part in the verification of a claim")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
            )
            (@subcommand subset =>
                (about: "Claims that a stack is a subset of another")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg SUBSET: +required "The name or identifier of the subset stack")
                (@arg SUPERSET: +required "The name or identifier of the superset stack")
            )
            (@subcommand superset =>
                (about: "Claims that a stack is a superset of another")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg SUPERSET: +required "The name or identifier of the superset stack")
                (@arg SUBSET: +required "The name or identifier of the subset stack")
            )
            (@subcommand disjoint =>
                (about: "Claims that two stacks are disjoint")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg STACK1: +required "The name or identifier of the first stack")
                (@arg STACK2: +required "The name or identifier of the second stack")
                (@arg UNIVERSE: +required "The name or identifier of the universe stack")
            )
        )
        (@subcommand rng =>
            (about: "Random number generation")
            (@setting DeriveDisplayOrder)
            (@setting ColoredHelp)
            (@setting SubcommandRequiredElseHelp)
            (@setting VersionlessSubcommands)
            (@setting DisableHelpSubcommand)
            (@subcommand new =>
                (about: "Initializes a new generator")
                (@setting DeriveDisplayOrder)
                (@setting ColoredHelp)
                (@arg NAME: +required "The name of the generator")
                (@arg SPEC: +required "The generator specification (e.g. 1d6+2)")
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
                (about: "Gets the generated random number from a generator")
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
        ("bin", Some(sub_m)) => bin::run(sub_m, &cfg),
        ("message", Some(sub_m)) => message::run(sub_m, &cfg),
        ("stack", Some(sub_m)) => stack::run(sub_m, &cfg),
        ("claim", Some(sub_m)) => claim::run(sub_m, &cfg),
        ("rng", Some(sub_m)) => rng::run(sub_m, &cfg),
        _ => Err(Error::InvalidSubcommand),
    }
    .unwrap_or_else(|e| e.exit());
}

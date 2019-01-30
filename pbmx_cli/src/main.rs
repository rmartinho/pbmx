#[macro_use]
extern crate clap;

fn main() {
    let matches = clap_app!(pbmx =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@subcommand init =>
            (about: "Initializes a new game folder")
            (version: "unimplemented")
            (@arg FOLDER: +required "The folder to hold game data")
        )
        (@subcommand issue =>
            (about: "Issues the current block")
            (version: "unimplemented")
        )
        (@subcommand msg =>
            (about: "Adds a message to the current block")
            (version: "unimplemented")
            (@arg MESSAGE: +required "The message")
        )
        (@subcommand bin =>
            (about: "Adds a binary blob to the current block")
            (version: "unimplemented")
            (@arg BASE64: +required "The blob in base64")
        )
        (@subcommand file =>
            (about: "Adds a the contents of a file to the current block")
            (version: "unimplemented")
            (@arg FILE: +required "The path to the file")
        )
        (@subcommand file =>
            (about: "Adds a the contents of a file to the current block")
            (version: "unimplemented")
            (@arg FILE: +required "The path to the file")
        )
        (@subcommand start =>
            (about: "Starts a game")
            (version: "unimplemented")
            (@arg NAME: +required "The name of the game")
        )
        (@subcommand join =>
            (about: "Joins the game")
            (version: "unimplemented")
        )
        (@subcommand stack =>
            (about: "Manipulates stacks")
            (version: "unimplemented")
            (@subcommand create =>
                (about: "Creates a new stack")
                (version: "unimplemented")
                (@arg TOKENS: +multiple +use_delimiter "The tokens in the stack")
                (@arg NAME: -n --name +takes_value "Sets the name of the stack")
                (@arg HIDDEN: -H --hidden conflicts_with[OPEN] "Makes the stack contents hidden from others")
                (@arg OPEN: -O --open conflicts_with[HIDDEN] "Makes the stack contents open to others (default)")
            )
            (@subcommand list =>
                (about: "Lists existing stacks")
                (version: "unimplemented")
                (@arg ALL: -a --all "Also includes unnamed stacks")
            )
            (@subcommand show =>
                (about: "Shows a stack's details")
                (version: "unimplemented")
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg VERBOSE: -v --verbose "Includes more details, e.g. encrypted data")
            )
            (@subcommand mask =>
                (about: "Remasks a stack")
                (version: "unimplemented")
                (@arg STACK: +required "The name or identifier of the stack")
            )
            (@subcommand shuffle =>
                (about: "Shuffles a stack")
                (version: "unimplemented")
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg ORDER: -o --order <INDICES> +multiple +use_delimiter "Chooses a specific order instead of randomizing")
            )
            (@subcommand cut =>
                (about: "Cuts a stack")
                (version: "unimplemented")
                (@arg STACK: +required "The name or identifier of the stack")
                (@arg N: -n +takes_value "Chooses a specific cut size instead of randomizing")
            )
            (@subcommand take =>
                (about: "Takes some tokens from an existing stack into another")
                (version: "unimplemented")
                (@arg SOURCE: +required "The name or identifier of the source stack")
                (@arg INDICES: +required +multiple +use_delimiter "The indices of the tokens to remove")
                (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stack")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
            )
            (@subcommand pile =>
                (about: "Piles several stacks together")
                (version: "unimplemented")
                (@arg STACKS: +required +multiple "The name or identifier of the source stacks, from top to bottom")
                (@arg TARGET: -t --to +takes_value "The name or identifier for the target stack")
                (@arg REMOVE: -r --remove conflicts_with[CLONE] "Remove the tokens from the source stacks")
                (@arg CLONE: -c --clone conflicts_with[REMOVE] "Clones the tokens into the target stack (default)")
            )
            (@subcommand reveal =>
                (about: "Reveals the secret share of a stack to others")
                (version: "unimplemented")
                (@arg STACK: +required "The name or identifier of the stack")
            )
        )
        (@subcommand random =>
            (about: "Handles distributed generation of shared random numbers")
            (version: "unimplemented")
            (@subcommand new =>
                (about: "Starts the generation of a new shared random number")
                (version: "unimplemented")
                (@arg BOUND: +required "The exclusive upper bound on the number")
            )
            (@subcommand add =>
                (about: "Adds a share in the generation of a shared random number")
                (version: "unimplemented")
                (@arg ID: +required "The identifier for the random number being generated")
            )
            (@subcommand gen =>
                (about: "Completes the generation of a shared random number")
                (version: "unimplemented")
                (@arg ID: +required "The identifier for the random number being generated")
            )
        )
    )
    .get_matches();
    dbg!(matches);
}

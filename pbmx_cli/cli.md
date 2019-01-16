The command-line tool provides a simple REPL-like interface to issue new blocks,
which can then be broadcast via any desired transport.

The following commands are available.

    > issue

Issues the current block and exits. The block is stored under blocks/ using the
block ID as the file name and its ID is printed before exiting.

    > msg <text>
    > bin <base64>
    > file <path>

Adds arbitrary data to a block. `msg` adds text messages, `bin` adds raw binary
data (provided in base64 format), and `file` adds the contents of a given file.

    > start <game> <players>

Starts a new game with the given number of players. The name of the game has no
meaning at the moment, but in the future it could be used to load the game's
rules from some database. This will generate a group and a key pair within that
group; the public key is published to initiate a key exchange.

    > join

Joins an existing game by generating a suitable key pair. The public key is
published. In the future, this would also support joining a game already in
progress.

    > stack <tokens>

Creates a face-up stack with the given tokens. The token specification is a
comma-separated list of token numbers, or of token ranges, denoted with a dash.
E.g. `stack 1-4,6` creates a stack with tokens 1, 2, 3, 4, and 6. The stack
contents, its ID, and a session-unique index are printed.

    > stackdown <tokens>

Creates a face-down stack with the given tokens. The token specification is as
for the `stack` command.

    > name <stack> <name>

Assigns a name to a stack. The stack is identified by its ID or its
session-unique index. This can e.g. be used to denoted the deck or each player's
hand when dealing. Stack names are unique, and can be reassigned to new stacks,
akin to git branches.

    > mask <stack>

(Re-)masks a stack. This is useful for certain less common scenarios, like
revealing a stack to a subset of players.

    > shuffle <stack> [<indices>]

Shuffles a stack, identified by its ID, session-unique index, or name. The
shuffle is either random, or according to the given indices. When shuffling a
stack by name, the name is reassigned to the resulting stack. The shuffled
stack's ID and session-unique index are printed.

    > cut <stack> [<n>]

"Cuts" a stack by moving a contiguous range of *n* tokens from the top to the
bottom. If no *n* is provided, it is selected randomly. *n* is, however, not
revealed to other players; the resulting block includes a proof that the cut is
correct, but does not reveal the number of tokens cut. As with shuffling, the
stack is identified by its ID, session-unique index, or name and when cuting a
stack by name, the name is reassigned to the resulting stack. The resulting
stack's ID and session-unique index are printed.

    > take <stack> <indices>

Takes the tokens at the given indices from the stack to form a new stack. When
the stack is identified by name, the name is reassigned to the stack without the
tokens. The indices are specified in the same manner as the tokens in the
`stack` command. The IDs and session-unique indices of the two resulting stacks
are printed.

    > pile <stack>...

Creates a new stack by piling the tokens from the given stacks in the order
given. The ID and session-unique index of the resulting stack is printed.

    > reveal <stack>

Reveals the decryption secrets for a given stack. This produces a new stack
where the tokens are no longer encrypted with those secrets; when all players do
this, the result is a face-up stack. When revealing a stack by name, the name is
reassigned to the resulting stack. The ID and session-unique index of the
resulting stack is printed.

    > rng <bound> [<description>]
    > rng <id>

Starts generation of a shared random number in the range [0, bound). A
description may be provided optionally. Prints an identifier for this random
number. When invoked with an identifier instead, contributes a random share
for that number. When all shares are provided, the random number is printed.


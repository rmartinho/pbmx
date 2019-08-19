# PBMX

PBMX is a framework for building secure and fair play-by-mail games without
trusted third-parties.

## Motivation

Consider this scenario: Alice is on the phone with Bob and the two want to bet
on the result of a coin flip. Since they are far apart, they cannot use a true
coin flip to settle the bet because there's no way for both of them to see the
coin. Can they do this in a way that guarantees that neither of them can
influence the result in their favour?

This is the simplest 'game' that can be implemented with the primitives
available in PBMX. Card games are the most obvious fit because of the
similarity in concepts, but many games can be simulated as card games under the
hood too. (As a trivial example, betting on a coin flip can be turned into
betting on the color of the top card in a regular deck of playing cards.)

*Random wip garbage follows*

## Notation

In the following, we will denote the elliptic curve generator by $G$ and
encryption of a message $m$ using a key $K$ and a blinding factor $r$ by
$E_K(m; r) = (r G, r K + m G)$.

Details of the zero-knowledge proofs are omitted in the interest of
succintness.

## Keys

Before a game can be played with PBMX, each player needs to generate a
private/public key pair. Each player secretly generates a random $x_i$ value as
a private key, and publishes $x_i G$ as their public key (where $G$ is the
curve generator). All the public keys are then added together to form a shared
public key $H=\sum{x_i G}$.

The corresponding private key would be $x = \sum{x_i}$ but computing that
requires the private keys of all of the players. In effect, no one holds this
shared private key.

Values can be encrypted using the shared public key as $c = (c_1, c_2) = E_H(m;
r)$. However, since no one holds the shared private key, decryption isn't
possible in the usual manner. To decrypt such, each player needs to publish a
decryption share $D_i(c) = x_i c_1$. Combining these shares allows decryption
without revealing the private keys $x_i$, using $m G = c_2 - \sum{D_i(c)}$.

## Tokens

PBMX fits naturally with card games but the actual concept used, the *token*,
is more abstract than that and can be used for any source of randomness and/or
hidden information in a game.

A token is just a 64-bit integer. Games using PBMX will define mappings between
the numbers and actual entities in the game (like cards).

## Masking

Tokens are only dealt with as user inputs or outputs. Otherwise, all operations
deal with *masks*. The *masking* operation is just encryption of the token
value as $c = E_H(t; r)$. A token can be hidden by many different masks, each
with a different blinding factor.

### Open-masking

Often one starts by *open-masking* all the tokens in the game (say, all cards
in a deck). Open-masking is a masking operation that does not actually hide the
tokens; it merely creates a mask for use by other operations. It works by
masking without a blinding factor, i.e. $E_H(t; 0)$. Any other player can
trivially verify the correctness of such a mask.

### Remasking

Any existing mask can be changed to a different mask without knowing nor
changing the value of the token being masked, by performing a *remasking*
operation, which only changes the blinding factor, as $M(c; r_1) = c + E_H(0;
r_1)$. If the original mask was obtained as $c = E_H(t; r_0)$, then the
remasked value is the same as $E_H(t; r_0+r_1)$, i.e., it masks the same token
with a combined blinding factor.

When remasking, a player could cheat and change the value of the masked token
to a different token $t'$ by calculating $E_H(t'; r')$ and pretending that was
the result of the remasking. Since the blinding factors cannot be shared, the
other players need some guarantee that a remasking was performed correctly and
did not change the token value. Every remasking is thus accompanied by a
zero-knowledge proof of its correctness, denoted $c_A \propto c_B$

### Unmasking

Revealing a masked token value is done by *unmasking*, which is simply
decrypting a mask which, as we saw above requires all players to publish
decryption shares $D_i(c)$ for that mask.

A player could, intentionally or accidentally, publish a wrong share. This
would go unnoticed and decrypt to the wrong value. For this reason all
decryption shares are also accompanied by a zero-knowledge proof of
correctness.

## Stacks

Masks can be arranged into stacks, which mimic physical stacks of cards. This
simplest arrangement sets existing masks in a specific order known to everyone.

### Shuffling

Because remasking requires a proof, it's easy to track changes in the order of
a stack across remaskings, so shuffling into a non-public order cannot be done
exclusively in terms of the other operations.

A shuffle $X_π(S; R)$ is produced by remasking all masks in the stack $S$ using
the blinding factors in $R$, i.e., $M(S[i]; R[i])$, and then reordering
according to the permutation $π$. The proofs of the remaskings are discarded as
they would allow tracking the order. Instead, a different proof is provided
that proves the shuffled stack contains all the same tokens in the same amounts
as in the original without regards to order.

Such a shuffle thus hides the new order from all but the player who performed
the shuffle. When a random shuffle that is unknown to everyone is needed, this
can be achieved by each player shuffling the stack in sequence, i.e., by doing
$S_i = X_{π_i}(S_{i-1}; R_i)$ for each player $i$. The final such stack has an
order that is unknown to everyone, as no one holds all the permutations and
blinding factors used. Furthermore, if at least one player uses uniformly
random permutations, then shuffles produced this way are uniformly random.

### Shifting

When playing physical card games, it is sometimes customary to "cut the deck".
This consists of taking an unknown number of cards from the top and moving them
to the bottom without changing their relative order. In a physical game this is
usually done as a quick and dirty way of thwarting attempts to "stack the deck"
on the part of the person shuffling. This is unnecessary with PBMX since a full
shuffle procedure already involves all players and prevents any one player from
"stacking the deck".  However, it turns out that this operation is still useful
as a building block for more complex operations.

In PBMX parlance, "cutting the deck" is called a *shift*. A shift $N_k(S; R)$
is produced by remasking all masks in the stack $S$ using the blinding factors
in $R$, i.e., $M(S[i]; R[i])$, and then cyclically shifting the positions of
those masks $k$ times. Similar to a shuffle, this operation discards the
regular remask proofs and instead uses a dedicated proof that the tokens are
the same and their relative orders are preserved.

Also akin to a shuffle, the performer of the shift operation knows the shift
amount $k$, but the other players don't. And also in the same fashion, this
knowledge can be erased by having each player perform successive shifts, i.e.
$S_i = N_{k_i}(S_{i-1}; R_i)$ for each player $i$.

### Inserting

Inserting a card into a secret position in a deck can be modelled by performing
a shift by some $k$, placing the card on top, and then performing a shift by
$-k$, i.e. undoing the shift. This can be trivially extended to inserting a
whole stack in a given position.

$I_k(S_n, S_h; R_1, R_2) = N_{-k}(S_n \parallel N_k(S_h; R_1); R_2)$

This cannot be built entirely out of existing primitives because the existing
proofs are not sufficient: it is also necessary to prove that the two shifts
are inverses of each other. This is accomplished by adding an additional proof
that one of the top or bottom tokens of the result is the same as it was before
insertion (without revealing which one is unchanged, so it is possible to
insert at the top or the bottom).

### Entangled operations

## Random


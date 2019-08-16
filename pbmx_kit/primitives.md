# PBMX basics

## Channels

PBMX assumes all communication happens on a public broadcast channel that all
players have access to. It is possible to use PBMX with private messages, but
working over a public broadcast channel is one of the design goals.

## Keys

PBMX uses elliptic curve keys for all cryptographic operations. Each player
generates a private/public key pair and publishes their public key. All public
keys are combined into a single shared public key. This shared public key is
then used for encryption. In theory, there is a shared private key that
corresponds to that shared public key; that private key could be obtained by
combining the private keys of all players. However, and this is a crucial
property of this scheme, as long as at least one player keeps their private key
hidden, no one can obtain that shared private key. Each player holds only a
*share* of that private key and all shares are needed to obtain it.

With these keys in place, anyone can encrypt things with the shared public key
but no one can decrypt it alone. Each player can elect to decrypt it with their
share of the private key, and if all players do so, this is the same as
decrypting it with the theoretical shared private key. These decryptions can be
performed without revealing any private keys. This enables players to encrypt
things that can only be decrypted if everyone agrees to it.

## Tokens & Masks & Stacks

The simplest entity that PBMX deals with is the *token*. A token is just a
64-bit number. Players have to agree on a mapping between those numbers and the
actual game entities involved. The closest physical equivalent to a token is a
face-up card.

Tokens can be masked by encrypting them with the shared public key. Such *masks*
completely hide the token from everyone but the player that encrypted it. The
closest physical equivalent to a mask is a face-down card; however, note that
unlike face-down cards, masks are distinct from each other, so it is possible to
track a mask as it moves from place to place, akin to a face-down card with a
mark.

Masks can be combined into *stacks*. A stack is just a sequence of masks. With a
stack it is possible to split, merge, and reorder masks without knowing nor
affecting the values of the underlying tokens. The closest physical equivalent
to a stack is a face-down deck of cards. However, using decryption operations,
stacks can also be used to represent face-up piles and players' hands.

## Token/Mask Operations

### Masking

Masking a token is done by merely encrypting it using the shared public key.

### Remasking

Remasking a mask is done by re-encrypting a mask using the shared public key.

### Unmasking

Unmasking a mask is done by each player providing a share of the decryption,
which is obtained using their own private keys. These shares are published
together with a proof of their correctness, so that errors (be they accidental
or deliberate) can be detected.

Unmasking can be done publicly for everyone if all players publish their
decryption shares. It can also be done for the exclusive benefit of a single
player if that player does not publish their share. This way the other players
have an incomplete set of shares, but that one player has a full set and thus
can decrypt the mask for themselves.

It is also possible to perform an unmasking for the exclusive benefit of more
than one player but not all, though this is a bit more involved. Suppose that in
a 3-player game, players A and B both get to look at a token, but player C does
not. A and B cannot both publish their decryption shares, because then C will
have a full set of shares and can thus decrypt the mask. However, if A remasks
the token, they can then publish their share of that remasking, while B
publishes a share of the original mask. This way C doesn't get a full set of
shares for any of the two maskings; A gets a full set of shares for the original
masking, and B gets a full set for the remasking.

## Stack Operations

### 

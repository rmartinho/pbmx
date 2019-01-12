PBMX is a framework to creating secure and fair games played over mail.

The main concern is supporting games that feature information that is secret,
unknown, or unavailable without the need for a trusted third party. *Secret
information* is information known to only a subset of the players; this could be
e.g. in a game of poker, the contents of a player's hand are secret. *Unknown
information* is information that no player knows; in a game of poker, the
contents of the deck are unknown. *Unavailable information* is information that
no player can obtain, even at the end of the game; in a game of poker, the
contents of the deck are not only unknown but also unavailable.

In order to achieve this, PBMX provides some cryptographic primitives for hiding
information and for proving that the hidden information is as expected, i.e. no
cheating happened. E.g. a player can produce a shuffled deck of cards and the
other players can verify that the shuffle does indeed have the correct cards in
it without actually knowing their order; were the original player to sneak in a
fifth ace, the other players would be able to tell that cheating happened
without having to check the contents of the shuffled deck.

Another concern of PBMX is the ability to play such games without requiring
real-time interaction, over a variety of transports. E-mail would be a
convenient and typical transport, but an attempt is made to fit the constraints
of snail mail.

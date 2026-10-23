# Capsul

A resilient, secure, misuse-resistant, and self-repairing P2P file storage program.

## What?

Capsul lets you create a network of peers to store files. Each of these peers can
store a select amount of data and are randomly chosen when a peer decides to store
a file. Files are split into chunks, then shards are created using a reed solomon
algorithm. These shards are authenticated, encrypted, and sent over the network
to peers to be stored. The peer ensures that each peer it's chosen has stored the
shard. Then if a peer goes offline or is malicious, the file that's originally
been stored can be recovered from its shards.

## Why?

For fun! And because there's an actual use for something like this. It lets you
securely distribute a file to an untrusted network of peers.


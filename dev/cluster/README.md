# Local 3-node cluster harness

A throwaway three-node Notary cluster for developing and testing the clustered
(dqlite) storage path. It exists because dqlite failure behaviour — leader
election, quorum loss, rejoin after a crash — cannot be exercised with a single
node or with unit tests.

Requirements: Docker, and a built frontend (`cd ui && bun install && bun run build`).

```sh
./harness.sh up            # build the image and binary, start three idle containers
./harness.sh bootstrap     # bootstrap the cluster on notary-1, create the admin account
./harness.sh join 2        # join notary-2 through the real token/CSR exchange
./harness.sh join 3
./harness.sh status
```

The containers stay idle and `harness.sh` starts, kills and restarts the Notary
process inside them. Killing a node therefore leaves its data directory intact,
which is what a crash looks like to the rest of the cluster:

```sh
./harness.sh kill 1 --hard   # simulate a node crashing
./harness.sh status 2        # the remaining members elect a new leader
./harness.sh restart 1       # it rejoins and catches up
```

The node APIs are published on `https://localhost:3001`, `:3002` and `:3003`.
The admin token is written to `build/admin-token` by `bootstrap`.

`./harness.sh down` removes the containers and their volumes.

The first `up` compiles dqlite from source and takes several minutes; later runs
reuse the image.

Everything under `build/` is generated, including the self-signed API
certificate shared by the three nodes. The cluster-internal PKI is not generated
here: Notary creates it itself on bootstrap and hands out node certificates
through the join exchange.

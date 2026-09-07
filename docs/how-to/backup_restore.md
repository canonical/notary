# Back up and restore Notary

Notary stores its data in the directory set by `db_path` in the [configuration file](../reference/config_file.md). Backup creates a `tar.gz` archive of that directory. Restore replaces the directory with the contents of an archive.

`notary backup` and `notary restore` are separate commands from the running server (`notary start`). Stop the Notary daemon first so the files on disk are consistent, then run backup or restore, then start the daemon again.

In a three-voter cluster, stop **one follower**, back up that member's `db_path` cold, then start it again. The remaining majority keeps serving. Do not take this backup while another voter is already down, and do not back up the only remaining voter.

```{warning}
`notary backup` and `notary restore` refuse to run while a Notary daemon still holds the data directory lock. Stop the daemon first so the files on disk are consistent. Copying a live dqlite directory can produce a corrupt archive or a corrupt restore.
```

## Prerequisites

* Notary installed (snap or a Notary binary)
* Disk space for the archive, which is roughly the size of the data directory

## 1. Stop Notary

`````{tab-set}

````{tab-item} Snap

```shell
sudo snap stop notary.notaryd
```

````

````{tab-item} Binary

Stop the `notary start` process (for example with Ctrl+C, or stop the systemd unit that runs it).

````

`````

## 2. Create a backup

The `-d` / `--db-path` flag is the data directory (`db_path`). The `-f` / `--file` flag must include a directory path; Notary writes a timestamped archive into that directory (for example `backup_20260831_120000.123456789.tar.gz`). That directory must be **outside** `db_path`, or the backup would include itself.

`````{tab-set}

````{tab-item} Snap

```shell
sudo mkdir -p /var/snap/notary/common/backups
sudo notary backup \
  --db-path /var/snap/notary/common/database \
  --file /var/snap/notary/common/backups/notary.tar.gz
```

````

````{tab-item} Binary

```shell
notary backup \
  --db-path /var/lib/notary/database \
  --file /var/backups/notary/notary.tar.gz
```

````

`````

The command prints the path of the archive it created.

## 3. Restore a backup

Restore deletes the current data directory and replaces it with the archive.

Treat every archive as a **cluster credential**. `cluster.key` lives in `db_path`, so the tarball can join the raft mesh and decrypt cluster TLS. Store and transport it like a private key, not like a convenience copy of the certificate files.

The archive also contains `info.yaml` (this node's raft identity) and `cluster.yaml` (the peer list at backup time). After restore, `cluster.address` and `cluster.name` must still match the node that was backed up. If you also keep copies of cluster TLS at `cluster.tls.cert_path` / `key_path` outside `db_path`, restore those files as well.

### Restore into a live cluster

Do **not** restore a follower archive onto a replacement machine and expect it to rejoin. The restored identity is already in the membership list with a stale view of peers.

1. On a surviving member, `notary cluster remove <name-or-dqlite-address>` (or **Remove** on the Cluster page).
2. On the replacement host, use an **empty** `db_path` and the **same** `cluster.name`.
3. `notary cluster add <name>` (or **Add member** in the UI) and `notary start --join '<token>'`.

In-place restore of the **same** member (same host, same `cluster.address` and `cluster.name`, still listed by the others) is only for recovering that node's disk. If it cannot catch up, remove it and join again as above.

### Restore after total cluster loss

A three-voter backup cannot elect a leader by itself: the restored node still expects two dead peers.

* If you still have archives for **every** member, restore each onto its original `cluster.address` / `cluster.name` and start them together.
* If you have only one usable member, restore it and then force it into a single-member cluster with [`notary cluster recover`](cluster.md#recover-from-quorum-loss). Stop Notary everywhere first, compare the raft position on each survivor, and recover the one that is furthest ahead. Rejoin the other machines afterwards with an empty `db_path` and a fresh join token.

`````{tab-set}

````{tab-item} Snap

```shell
sudo notary restore \
  --db-path /var/snap/notary/common/database \
  --file /var/snap/notary/common/backups/backup_20260831_120000.tar.gz
```

````

````{tab-item} Binary

```shell
notary restore \
  --db-path /var/lib/notary/database \
  --file /var/backups/notary/backup_20260831_120000.tar.gz
```

````

`````

## 4. Start Notary

`````{tab-set}

````{tab-item} Snap

```shell
sudo snap start notary.notaryd
```

````

````{tab-item} Binary

```shell
notary start --config /path/to/config.yaml
```

````

`````

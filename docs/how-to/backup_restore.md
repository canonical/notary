# Back up and restore Notary

Notary stores its data in the directory set by `db_path` in the [configuration file](../reference/config_file.md). Backup creates a `tar.gz` archive of that directory. Restore replaces the directory with the contents of an archive.

`notary backup` and `notary restore` are separate commands from the running server (`notary start`). Stop the Notary daemon first so the files on disk are consistent, then run backup or restore, then start the daemon again.

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

Restore deletes the current data directory and replaces it with the archive. After restore, `cluster.address` and `cluster.name` in the configuration file must still match the node that was backed up.

Cluster TLS files (`cluster.tls.cert_path` and `cluster.tls.key_path`) live next to the configuration file, not inside `db_path`. Keep the same `cluster.crt` and `cluster.key` the node used before the backup. Backup does not archive those files unless you stored them in the data directory yourself.

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

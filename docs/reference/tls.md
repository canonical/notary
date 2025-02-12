# TLS

Notary uses TLS to secure its API and web interface. The use of TLS is mandatory, Notary will not start if the TLS configuration is missing or invalid.

## Configuration

The TLS configuration is defined in the [configuration file](config_file.md). 

## Certificate Renewal

After replacing the certificate and key file, Notary must be restarted to apply the changes.

## Supported TLS Versions

Notary supports TLS versions `1.2` and `1.3`.

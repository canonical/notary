# Roles

Notary uses a role-based access control (RBAC) system to manage permissions for users. Each role is defined with a set of permissions that determine what actions users can perform within Notary.

- **Admin**: Full access to all Notary features.
- **Certificate Manager**: Can manage Certificate Authorities, read Certificate Requests, and issue and revoke certificates.
- **Certificate Requestor**: Can create and read Certificate Requests.
- **Read Only**: Can read everything.

Roles are assigned to accounts when they are created, either via the API (see the [API account reference](api/accounts.md)) or the web interface.

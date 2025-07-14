# Roles

Notary uses a role-based access control (RBAC) system to manage permissions for users. Each role is defined with a set of permissions that determine what actions users can perform within Notary.

- **Admin**: Full access to all Notary features.
- **Certificate Manager**: Can manage Certificate Authorities, Certificate Requests, issue and revoke certificates.
- **Certificate Requestor**: Can create Certificate Requests and view their own requests.
- **Read Only**: Can read everything except accounts.

Roles are assigned to accounts when they are created, either via the API (see the [API account reference](api/accounts.md#create-an-account)) or the web interface.

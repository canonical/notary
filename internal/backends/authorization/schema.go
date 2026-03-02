package authorization

const OFGAModel = `
model
  schema 1.1

type user

type system
  relations
    define admin:                  [user]
    define certificate_manager:    [user] or admin
    define certificate_requestor:  [user] or certificate_manager
    define reader:                 [user] or certificate_manager
`

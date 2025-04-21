export type CSREntry = {
    id: number,
    csr: string,
    certificate_chain: string
    status: "Outstanding" | "Active" | "Rejected" | "Revoked"
}

export type CertificateAuthorityEntry = {
    id: number,
    status: "active" | "expired" | "pending" | "legacy"
    certificate: string
    csr: string
    crl: string
}

export type User = {
    exp: number
    id: number
    permissions: number
    username: string
    authToken: string

    activeCA: number
}

export type UserEntry = {
    id: number
    username: string
}

export type statusResponse = {
    initialized: boolean
    version: string
}

export type AsideFormData = {
    formTitle: string
    formData: any
}
export type CSREntry = {
    id: number,
    csr: string,
    certificate_chain: string
    status: "Outstanding" | "Active" | "Rejected" | "Revoked"
}

export type User = {
    exp: number
    id: number
    permissions: number
    username: string
    authToken: string
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
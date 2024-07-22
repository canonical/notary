export type CSREntry = {
    id: number,
    csr: string,
    certificate: string
}

export type User = {
    exp: number
    id: number
    permissions: number
    username: string
}
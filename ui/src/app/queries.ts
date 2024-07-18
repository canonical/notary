import { CSREntry } from "./types"

export type RequiredParams = {
    id: string
    authToken: string
    csr?: string
    cert?: string
}

export async function getCertificateRequests(params: { authToken: string }): Promise<CSREntry[]> {
    const response = await fetch("/api/v1/certificate_requests", {
        headers: { "Authorization": "Bearer " + params.authToken }
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function postCSR(params: {authToken: string, csr: string}) {
    if (!params.csr) {
        throw new Error('CSR not provided')
    }
    const response = await fetch("/api/v1/certificate_requests", {
        method: 'post',
        headers: {
            'Content-Type': 'text/plain',
            'Authorization': "Bearer " + params.authToken
        },
        body: params.csr.trim()
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function postCertToID(params: RequiredParams) {
    if (!params.cert) {
        throw new Error('Certificate not provided')
    }
    const response = await fetch("/api/v1/certificate_requests/" + params.id + "/certificate", {
        method: 'post',
        headers: {
            'Content-Type': 'text/plain',
            'Authorization': "Bearer " + params.authToken
        },
        body: params.cert.trim()
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function deleteCSR(params: RequiredParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id, {
        method: 'delete',
        headers: {
            'Authorization': "Bearer " + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function rejectCSR(params: RequiredParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id + "/certificate/reject", {
        method: 'post',
        headers: {
            'Authorization': "Bearer " + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function revokeCertificate(params: RequiredParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id + "/certificate/reject", {
        method: 'post',
        headers: {
            'Authorization': 'Bearer ' + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}

export async function login(userForm: { username: string, password: string }) {
    const response = await fetch("/login", {
        method: "POST",
        body: JSON.stringify({ "username": userForm.username, "password": userForm.password })
    })
    if (!response.ok) {
        const responseText = await response.text()
        throw new Error(responseText)
    }
    return response.text()
}
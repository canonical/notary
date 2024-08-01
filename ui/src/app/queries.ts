import { CSREntry, UserEntry } from "./types"
import { HTTPStatus } from "./utils"

export type RequiredCSRParams = {
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
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function postCSR(params: { authToken: string, csr: string }) {
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
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function postCertToID(params: RequiredCSRParams) {
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
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function deleteCSR(params: RequiredCSRParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id, {
        method: 'delete',
        headers: {
            'Authorization': "Bearer " + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function rejectCSR(params: RequiredCSRParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id + "/certificate/reject", {
        method: 'post',
        headers: {
            'Authorization': "Bearer " + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function revokeCertificate(params: RequiredCSRParams) {
    const response = await fetch("/api/v1/certificate_requests/" + params.id + "/certificate/reject", {
        method: 'post',
        headers: {
            'Authorization': 'Bearer ' + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function login(userForm: { username: string, password: string }) {
    const response = await fetch("/login", {
        method: "POST",

        body: JSON.stringify({ "username": userForm.username, "password": userForm.password })
    })
    const responseText = await response.text()
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}. ${responseText}`)
    }
    return responseText
}

export async function changeSelfPassword(changePasswordForm: { authToken: string, password: string }) {
    const response = await fetch("/api/v1/accounts/me/change_password", {
        method: "POST",
        headers: {
            'Authorization': 'Bearer ' + changePasswordForm.authToken
        },
        body: JSON.stringify({ "password": changePasswordForm.password })
    })
    const responseText = await response.text()
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}. ${responseText}`)
    }
    return responseText
}

export async function changePassword(changePasswordForm: { authToken: string, id: string, password: string }) {
    const response = await fetch("/api/v1/accounts/" + changePasswordForm.id + "/change_password", {
        method: "POST",
        headers: {
            'Authorization': 'Bearer ' + changePasswordForm.authToken
        },
        body: JSON.stringify({ "password": changePasswordForm.password })
    })
    const responseText = await response.text()
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}. ${responseText}`)
    }
    return responseText
}

export async function getUsers(params: { authToken: string }): Promise<UserEntry[]> {
    const response = await fetch("/api/v1/accounts", {
        headers: { "Authorization": "Bearer " + params.authToken }
    })
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function deleteUser(params: { authToken: string, id: string }) {
    const response = await fetch("/api/v1/accounts/" + params.id, {
        method: 'delete',
        headers: {
            'Authorization': "Bearer " + params.authToken
        }
    })
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}`)
    }
    return response.json()
}

export async function postUser(userForm: { authToken: string, username: string, password: string }) {
    const response = await fetch("/api/v1/accounts", {
        method: "POST",
        headers: {
            'Authorization': "Bearer " + userForm.authToken
        },
        body: JSON.stringify({ "username": userForm.username, "password": userForm.password })
    })
    const responseText = await response.text()
    if (!response.ok) {
        throw new Error(`${response.status}: ${HTTPStatus(response.status)}. ${responseText}`)
    }
    return responseText
}
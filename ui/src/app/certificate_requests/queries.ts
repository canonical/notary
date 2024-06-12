import { CSREntry } from "./types"

export async function getCertificateRequests(): Promise<CSREntry[]> {
    const response = await fetch("/api/v1/certificate_requests")
    if (!response.ok) {
        throw new Error('Network response was not ok')
    }
    return response.json()
}
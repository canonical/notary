"use client"

import { useQuery } from "react-query"
import { CertificateRequestsTable } from "./table"
import { getCertificateRequests } from "./queries"
import { CSREntry } from "./types"

export default function CertificateRequests() {
    const query = useQuery<CSREntry[], Error>('csrs', getCertificateRequests)
    if (query.status == "loading"){ return <div>Loading...</div> }
    if (query.status == "error") { return <div>error :(</div>}
    if (query.data == undefined) { return <div>No data</div>}
    const csrs = Array.from(query.data)
    return (
        <CertificateRequestsTable csrs={csrs}/>
    )
}
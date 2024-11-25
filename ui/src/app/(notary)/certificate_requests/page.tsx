"use client"

import { useQuery } from "@tanstack/react-query"
import { CertificateRequestsTable } from "./table"
import { getCertificateRequests } from "@/queries"
import { CSREntry } from "@/types"
import Loading from "@/components/loading"
import Error from "@/components/error"
import { useAuth } from "@/hooks/useAuth"
import { retryExceptWhenUnauthorized } from "@/utils"


export default function CertificateRequests() {
    const auth = useAuth()
    const query = useQuery<CSREntry[], Error>({
        queryKey: ['csrs', auth.user?.authToken],
        queryFn: () => getCertificateRequests({ authToken: auth.user ? auth.user.authToken : "" }),
        retry: retryExceptWhenUnauthorized,
        enabled: !!auth.user
    })
    if (query.status == "pending") { return <Loading /> }
    if (query.status == "error") {
        if (query.error.message.includes("401")) {
            auth.logout()
        }
        return <Error msg={query.error.message} />
    }
    const csrs = Array.from(query.data ? query.data : [])
    return (
        <CertificateRequestsTable csrs={csrs} />
    )
}
"use client"

import { useQuery } from "@tanstack/react-query"
import { CertificateRequestsTable } from "./table"
import { getCertificateRequests } from "@/queries"
import { CSREntry } from "@/types"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"
import Loading from "@/components/loading"
import Error from "@/components/error"


export default function CertificateRequests() {
    const router = useRouter()
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    if (!cookies.user_token) {
        router.push("/login")
    }
    const query = useQuery<CSREntry[], Error>({
        queryKey: ['csrs', cookies.user_token],
        queryFn: () => getCertificateRequests({ authToken: cookies.user_token }),
        retry: (failureCount, error): boolean => {
            if (error.message.includes("401")) {
                return false
            }
            return true
        },
    })
    if (query.status == "pending") { return <Loading /> }
    if (query.status == "error") {
        if (query.error.message.includes("401")) {
            removeCookie("user_token")
        }
        return <Error msg={query.error.message} />
    }
    const csrs = Array.from(query.data ? query.data : [])
    return (
        <CertificateRequestsTable csrs={csrs} />
    )
}
"use client"

import { useQuery } from "react-query"
import { CertificateRequestsTable } from "./table"
import { getCertificateRequests } from "../queries"
import { CSREntry } from "../types"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"

function Error({ msg }: { msg: string }) {
    return (
        <caption>
            <div className="p-strip">
                <div className="row">
                    <div className="u-align--left">
                        <p className="p-heading--5">An error occured trying to load certificate requests</p>
                        <p>{msg}</p>
                    </div>
                </div>
            </div>
        </caption>
    )
}

function Loading() {
    return (
        <caption>
            <div className="p-strip">
                <div className="row">
                    <div className="col-8 col-medium-4 col-small-3">
                        <p className="p-heading--4 u-no-margin--bottom">Loading...</p>
                    </div>
                </div>
            </div>
        </caption>
    )
}

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
    if (query.status == "loading") { return <Loading /> }
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
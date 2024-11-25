"use client"

import { useQuery } from "@tanstack/react-query"
import { ListUsers } from "@/queries"
import { UserEntry } from "@/types"
import { UsersTable } from "./table"
import Loading from "@/components/loading"
import Error from "@/components/error"
import { useAuth } from "@/hooks/useAuth"
import { retryExceptWhenUnauthorized } from "@/utils"

export default function Users() {
    const auth = useAuth()
    const query = useQuery<UserEntry[], Error>({
        queryKey: ['users', auth.user ? auth.user.authToken : ""],
        queryFn: () => ListUsers({ authToken: auth.user ? auth.user.authToken : "" }),
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
    const users = Array.from(query.data ? query.data : [])
    return <UsersTable users={users} />
}
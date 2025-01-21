"use client"

import { useQuery } from "@tanstack/react-query"
import { CertificateRequestsTable } from "./table"
import { getCertificateRequests } from "@/queries"
import { CSREntry } from "@/types"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"
import Loading from "@/components/loading"
import Error from "@/components/error"
import { useState } from "react"
import { AppAside, Application, AppMain } from "@canonical/react-components"
import CertificateRequestsAsidePanel from "./asideForm"
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars"
import { retryUnlessUnauthorized } from "@/utils"
import NotaryAppStatus from "@/components/NotaryAppStatus"


export default function CertificateRequestsPanel() {
  const router = useRouter()
  const [asideOpen, setAsideOpen] = useState<boolean>(false)
  const [cookies, setCookie, removeCookie] = useCookies(['user_token']);

  if (!cookies.user_token) {
    router.push("/login")
  }

  const query = useQuery<CSREntry[], Error>({
    queryKey: ['csrs', cookies.user_token],
    queryFn: () => getCertificateRequests({ authToken: cookies.user_token }),
    retry: retryUnlessUnauthorized,
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
    <Application>
      <NotaryAppNavigationBars />
      <AppAside collapsed={!asideOpen}>
        <CertificateRequestsAsidePanel setAsideOpen={setAsideOpen} />
      </AppAside>
      <AppMain>
        <CertificateRequestsTable csrs={csrs} setAsideOpen={setAsideOpen} />
      </AppMain>
      <NotaryAppStatus />
    </Application>
  )
}
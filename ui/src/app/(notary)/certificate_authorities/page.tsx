"use client";

import { useQuery } from "@tanstack/react-query";
import { CertificateAuthoritiesTable } from "./table";
import { getCertificateAuthorities } from "@/queries";
import { CertificateAuthorityEntry } from "@/types";
import { useCookies } from "react-cookie";
import { useRouter } from "next/navigation";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import { AppAside, Application, AppMain } from "@canonical/react-components";
import CertificateAuthoritiesAsidePanel from "./asideForm";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { retryUnlessUnauthorized } from "@/utils";
import NotaryAppStatus from "@/components/NotaryAppStatus";
import { useAuth } from "@/hooks/useAuth";

export default function CertificateRequestsPanel() {
  const router = useRouter();
  const auth = useAuth();
  const [asideOpen, setAsideOpen] = useState<boolean>(false);
  const [cookies, , removeCookie] = useCookies(["user_token"]);

  if (!cookies.user_token) {
    router.push("/login");
  }

  const query = useQuery<CertificateAuthorityEntry[], Error>({
    queryKey: ["cas", auth.user ? auth.user.authToken : ""],
    queryFn: () =>
      getCertificateAuthorities({
        authToken: auth.user ? auth.user.authToken : "",
      }),
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    if (query.error.message.includes("401")) {
      removeCookie("user_token");
    }
    return <Error msg={query.error.message} />;
  }
  const cas = Array.from(query.data ? query.data : []);
  return (
    <Application>
      <NotaryAppNavigationBars />
      <AppAside collapsed={!asideOpen} pinned={true}>
        <CertificateAuthoritiesAsidePanel setAsideOpen={setAsideOpen} />
      </AppAside>
      <AppMain>
        <CertificateAuthoritiesTable cas={cas} setAsideOpen={setAsideOpen} />
      </AppMain>
      <NotaryAppStatus />
    </Application>
  );
}

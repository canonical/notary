"use client";

import { useQuery } from "@tanstack/react-query";
import { CertificateAuthoritiesTable } from "./table";
import { getCertificateAuthorities } from "@/queries";
import { CertificateAuthorityEntry } from "@/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import { AppAside, Application, AppMain } from "@canonical/react-components";
import CertificateAuthoritiesAsidePanel from "./asideForm";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { retryUnlessUnauthorized } from "@/utils";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export default function CertificateRequestsPanel() {
  const [asideOpen, setAsideOpen] = useState<boolean>(false);

  const query = useQuery<CertificateAuthorityEntry[], Error>({
    queryKey: ["cas"],
    queryFn: getCertificateAuthorities,
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
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

"use client";

import { useQuery } from "@tanstack/react-query";
import { CertificateRequestsTable } from "./table";
import { getCertificateRequests } from "@/queries";
import { CSREntry } from "@/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import { AppAside, Application, AppMain } from "@canonical/react-components";
import CertificateRequestsAsidePanel from "./asideForm";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export default function CertificateRequestsPanel() {
  const [asideOpen, setAsideOpen] = useState<boolean>(false);

  const query = useQuery<CSREntry[], Error>({
    queryKey: ["csrs"],
    queryFn: getCertificateRequests,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={query.error.message} />;
  }
  const csrs = Array.from(query.data ? query.data : []);
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
  );
}

"use client";

import { useQuery } from "@tanstack/react-query";
import { CertificateRequestsTable } from "./table";
import { getCertificateRequests } from "@/queries";
import { CSREntry, getErrorMessage } from "@/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import {
  Application,
  AppMain,
  ToastNotificationProvider,
} from "@canonical/react-components";
import CertificateRequestsAside from "./aside";
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
    return <Error msg={getErrorMessage(query.error)} />;
  }
  const csrs = Array.from(query.data ? query.data : []);
  return (
    <Application>
      <ToastNotificationProvider>
        <NotaryAppNavigationBars />
        <CertificateRequestsAside
          asideIsOpen={asideOpen}
          setAsideIsOpen={setAsideOpen}
        />
        <AppMain>
          <CertificateRequestsTable csrs={csrs} setAsideOpen={setAsideOpen} />
        </AppMain>
        <NotaryAppStatus />
      </ToastNotificationProvider>
    </Application>
  );
}

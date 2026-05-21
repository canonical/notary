import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CertificateRequestsTable } from "./-components/table";
import CertificateRequestsAsidePanel from "./-components/asideForm";
import { getCertificateRequests } from "@/utils/queries";
import { type CSREntry, getErrorMessage } from "@/utils/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import {
  AppAside,
  Application,
  AppMain,
  ToastNotificationProvider,
} from "@canonical/react-components";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export const Route = createFileRoute("/certificate_requests")({
  component: CertificateRequestsPageComponent,
});

function CertificateRequestsPageComponent() {
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
        <AppAside collapsed={!asideOpen}>
          <CertificateRequestsAsidePanel setAsideOpen={setAsideOpen} />
        </AppAside>
        <AppMain>
          <CertificateRequestsTable csrs={csrs} setAsideOpen={setAsideOpen} />
        </AppMain>
        <NotaryAppStatus />
      </ToastNotificationProvider>
    </Application>
  );
}

import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CertificateAuthoritiesTable } from "./-components/table";
import { getCertificateAuthorities } from "@/utils/queries";
import {
  type APIError,
  type CertificateAuthorityEntry,
  getErrorMessage,
} from "@/utils/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import {
  AppAside,
  Application,
  AppMain,
  ToastNotificationProvider,
} from "@canonical/react-components";
import CertificateAuthoritiesAsidePanel from "./-components/asideForm";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { retryUnlessUnauthorized } from "@/utils/helpers";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export const Route = createFileRoute("/certificate_authorities")({
  component: CertificateRequestsPageComponent,
});

function CertificateRequestsPageComponent() {
  const [asideOpen, setAsideOpen] = useState<boolean>(false);

  const query = useQuery<CertificateAuthorityEntry[], APIError>({
    queryKey: ["cas"],
    queryFn: getCertificateAuthorities,
    retry: retryUnlessUnauthorized,
  });
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={getErrorMessage(query.error)} />;
  }
  const cas = Array.from(query.data ? query.data : []);
  return (
    <Application>
      <ToastNotificationProvider>
        <NotaryAppNavigationBars />
        <AppAside collapsed={!asideOpen}>
          <CertificateAuthoritiesAsidePanel setAsideOpen={setAsideOpen} />
        </AppAside>
        <AppMain>
          <CertificateAuthoritiesTable cas={cas} setAsideOpen={setAsideOpen} />
        </AppMain>
        <NotaryAppStatus />
      </ToastNotificationProvider>
    </Application>
  );
}

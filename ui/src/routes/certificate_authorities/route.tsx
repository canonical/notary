import {
	AppAside,
	Application,
	AppMain,
	ToastNotificationProvider,
} from "@canonical/react-components";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import ErrorComponent from "@/components/error";
import Loading from "@/components/loading";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import NotaryAppStatus from "@/components/NotaryAppStatus";
import { retryUnlessUnauthorized } from "@/utils/helpers";
import { getCertificateAuthorities } from "@/utils/queries";
import {
	type APIError,
	type CertificateAuthorityEntry,
	getErrorMessage,
} from "@/utils/types";
import CertificateAuthoritiesAsidePanel from "./-components/asideForm";
import { CertificateAuthoritiesTable } from "./-components/table";

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
	if (query.status === "pending") {
		return <Loading />;
	}
	if (query.status === "error") {
		return <ErrorComponent msg={getErrorMessage(query.error)} />;
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

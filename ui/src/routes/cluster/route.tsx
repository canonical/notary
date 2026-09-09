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
import { getClusterMembers } from "@/utils/queries";
import { type ClusterMemberEntry, getErrorMessage } from "@/utils/types";
import ClusterPageAsidePanel from "./-components/asideForm";
import { ClusterTable } from "./-components/table";

export const Route = createFileRoute("/cluster")({
	component: ClusterPageComponent,
});

function ClusterPageComponent() {
	const [asideOpen, setAsideOpen] = useState<boolean>(false);
	const query = useQuery<ClusterMemberEntry[], Error>({
		queryKey: ["cluster"],
		queryFn: getClusterMembers,
		retry: retryUnlessUnauthorized,
		// Membership changes without user action: a joiner appears when another
		// machine starts with --join, and dqlite promotes spares to voters itself.
		refetchInterval: 5000,
	});
	if (query.status === "pending") {
		return <Loading />;
	}
	if (query.status === "error") {
		return <ErrorComponent msg={getErrorMessage(query.error)} />;
	}
	const members = Array.from(query.data ? query.data : []);
	return (
		<Application>
			<ToastNotificationProvider>
				<NotaryAppNavigationBars />
				<AppAside collapsed={!asideOpen}>
					<ClusterPageAsidePanel setAsideOpen={setAsideOpen} />
				</AppAside>
				<AppMain>
					<ClusterTable members={members} setAsideOpen={setAsideOpen} />
				</AppMain>
				<NotaryAppStatus />
			</ToastNotificationProvider>
		</Application>
	);
}

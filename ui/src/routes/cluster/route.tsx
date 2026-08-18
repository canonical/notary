import {
	Application,
	AppMain,
	Panel,
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
import { type GETStatus, getClusterStatus, getStatus } from "@/utils/queries";
import {
	type APIError,
	type ClusterStatusEntry,
	getErrorMessage,
} from "@/utils/types";
import { AddNodeModal } from "./-components/addNodeModal";
import { ClusterTable } from "./-components/table";

export const Route = createFileRoute("/cluster")({
	component: ClusterPageComponent,
});

function ClusterPageComponent() {
	const [addNodeOpen, setAddNodeOpen] = useState<boolean>(false);

	const statusQuery = useQuery<GETStatus, APIError>({
		queryKey: ["status"],
		queryFn: getStatus,
		retry: retryUnlessUnauthorized,
	});
	// Clustering is not something the operator toggles from here, so a missing
	// node ID is a stable answer, not a transient one: the API would only ever
	// return 404 for every cluster route.
	const clusteringEnabled = Boolean(statusQuery.data?.node_id);
	const clusterQuery = useQuery<ClusterStatusEntry, APIError>({
		queryKey: ["cluster_status"],
		queryFn: getClusterStatus,
		retry: retryUnlessUnauthorized,
		enabled: clusteringEnabled,
		// Leadership and roles change without anyone touching this page.
		refetchInterval: 10000,
	});

	if (statusQuery.status === "pending") {
		return <Loading />;
	}
	if (statusQuery.status === "error") {
		return <ErrorComponent msg={getErrorMessage(statusQuery.error)} />;
	}

	let content: React.ReactNode;
	if (!clusteringEnabled) {
		content = (
			<Panel stickyHeader title="Cluster" className="u-fixed-width">
				<p>
					Clustering is not enabled on this node. Set{" "}
					<code>cluster.enabled</code> in the configuration file and run{" "}
					<code>notary cluster bootstrap</code> to start a cluster.
				</p>
			</Panel>
		);
	} else if (clusterQuery.status === "pending") {
		content = <Loading />;
	} else if (clusterQuery.status === "error") {
		content = <ErrorComponent msg={getErrorMessage(clusterQuery.error)} />;
	} else {
		content = (
			<ClusterTable
				status={clusterQuery.data}
				localNodeID={statusQuery.data.node_id ?? ""}
				localNodeSealed={statusQuery.data.sealed}
				onAddNode={() => setAddNodeOpen(true)}
			/>
		);
	}

	return (
		<Application>
			<ToastNotificationProvider>
				<NotaryAppNavigationBars />
				<AppMain>{content}</AppMain>
				{addNodeOpen && (
					<AddNodeModal
						close={() => setAddNodeOpen(false)}
						apiAddress={window.location.host}
					/>
				)}
				<NotaryAppStatus />
			</ToastNotificationProvider>
		</Application>
	);
}

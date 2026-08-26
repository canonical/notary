import {
	Application,
	AppMain,
	Notification,
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
		// Losing the leader is exactly when this page matters, and it is exactly
		// when the cluster-wide view cannot be built. What this node knows about
		// itself still comes from /status, so it is shown rather than replaced
		// with an error that says nothing about where the node stands.
		content = (
			<Panel stickyHeader title="Cluster" className="u-fixed-width">
				<Notification severity="negative" title="Cluster view unavailable">
					{getErrorMessage(clusterQuery.error)}
				</Notification>
				<p className="u-text--muted">
					The cluster-wide view needs the Raft leader. This node is still
					running, and reports the following about itself.
				</p>
				<dl>
					<dt>Node ID</dt>
					<dd>{statusQuery.data.node_id}</dd>
					<dt>Role</dt>
					<dd>{statusQuery.data.role ?? "unknown"}</dd>
					<dt>Raft state</dt>
					<dd>{statusQuery.data.raft_state ?? "unknown"}</dd>
					<dt>Seal state</dt>
					<dd>{statusQuery.data.sealed ? "Sealed" : "Unsealed"}</dd>
				</dl>
			</Panel>
		);
	} else {
		content = (
			<ClusterTable
				status={clusterQuery.data}
				localNodeID={statusQuery.data.node_id ?? ""}
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

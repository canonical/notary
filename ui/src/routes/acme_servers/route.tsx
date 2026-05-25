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
import { getACMEServers } from "@/utils/queries";
import {
	type ACMEServerEntry,
	type APIError,
	getErrorMessage,
} from "@/utils/types";
import ACMEServersAsidePanel from "./-components/asideForm";
import ACMEServersTable from "./-components/table";

export const Route = createFileRoute("/acme_servers")({
	component: ACMEServersPageComponent,
});

function ACMEServersPageComponent() {
	const [asideOpen, setAsideOpen] = useState<boolean>(false);
	const [editingServer, setEditingServer] = useState<ACMEServerEntry | null>(
		null,
	);

	const query = useQuery<ACMEServerEntry[], APIError>({
		queryKey: ["acme_servers"],
		queryFn: getACMEServers,
		retry: retryUnlessUnauthorized,
	});

	if (query.status === "pending") {
		return <Loading />;
	}
	if (query.status === "error") {
		return <ErrorComponent msg={getErrorMessage(query.error)} />;
	}

	const servers = Array.from(query.data ?? []);

	const handleEdit = (server: ACMEServerEntry) => {
		setEditingServer(server);
		setAsideOpen(true);
	};

	const handleClose = () => {
		setAsideOpen(false);
		setEditingServer(null);
	};

	return (
		<Application>
			<ToastNotificationProvider>
				<NotaryAppNavigationBars />
				<AppAside collapsed={!asideOpen}>
					<ACMEServersAsidePanel
						setAsideOpen={handleClose}
						editingServer={editingServer}
					/>
				</AppAside>
				<AppMain>
					<ACMEServersTable
						servers={servers}
						setAsideOpen={setAsideOpen}
						onEdit={handleEdit}
					/>
				</AppMain>
				<NotaryAppStatus />
			</ToastNotificationProvider>
		</Application>
	);
}

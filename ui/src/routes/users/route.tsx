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
import { ListUsers } from "@/utils/queries";
import {
	type AsideFormData,
	getErrorMessage,
	type UserEntry,
} from "@/utils/types";
import UsersPageAsidePanel from "./-components/asideForm";
import { UsersTable } from "./-components/table";

export const Route = createFileRoute("/users")({
	component: UsersPageComponent,
});

function UsersPageComponent() {
	const [asideOpen, setAsideOpen] = useState<boolean>(false);
	const [formData, setFormData] = useState<AsideFormData>({
		formTitle: "Add a New User",
	});
	const query = useQuery<UserEntry[], Error>({
		queryKey: ["users"],
		queryFn: ListUsers,
		retry: retryUnlessUnauthorized,
	});
	if (query.status === "pending") {
		return <Loading />;
	}
	if (query.status === "error") {
		return <ErrorComponent msg={getErrorMessage(query.error)} />;
	}
	const users = Array.from(query.data ? query.data : []);
	return (
		<Application>
			<ToastNotificationProvider>
				<NotaryAppNavigationBars />
				<AppAside collapsed={!asideOpen}>
					<UsersPageAsidePanel
						setAsideOpen={setAsideOpen}
						formData={formData}
					/>
				</AppAside>
				<AppMain>
					<UsersTable
						users={users}
						setAsideOpen={setAsideOpen}
						setFormData={setFormData}
					/>
				</AppMain>
				<NotaryAppStatus />
			</ToastNotificationProvider>
		</Application>
	);
}

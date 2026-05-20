import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ListUsers } from "@/utils/queries";
import {
  type AsideFormData,
  type UserEntry,
  getErrorMessage,
} from "@/utils/types";
import { UsersTable } from "./-components/table";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { retryUnlessUnauthorized } from "@/utils/helpers";
import {
  AppMain,
  ToastNotificationProvider,
} from "@canonical/react-components";
import { AppAside } from "@canonical/react-components";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { Application } from "@canonical/react-components";
import NotaryAppStatus from "@/components/NotaryAppStatus";
import { useState } from "react";
import UsersPageAsidePanel from "./-components/asideForm";

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
  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={getErrorMessage(query.error)} />;
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

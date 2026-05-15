"use client";

import { useQuery } from "@tanstack/react-query";
import { getACMEServers } from "@/queries";
import { ACMEServerEntry, APIError, getErrorMessage } from "@/types";
import Loading from "@/components/loading";
import Error from "@/components/error";
import { useState } from "react";
import {
  AppAside,
  Application,
  AppMain,
  ToastNotificationProvider,
} from "@canonical/react-components";
import ACMEServersAsidePanel from "./asideForm";
import ACMEServersTable from "./table";
import NotaryAppNavigationBars from "@/components/NotaryAppNavigationBars";
import { retryUnlessUnauthorized } from "@/utils";
import NotaryAppStatus from "@/components/NotaryAppStatus";

export default function ACMEServersPage() {
  const [asideOpen, setAsideOpen] = useState<boolean>(false);
  const [editingServer, setEditingServer] = useState<ACMEServerEntry | null>(
    null,
  );

  const query = useQuery<ACMEServerEntry[], APIError>({
    queryKey: ["acme_servers"],
    queryFn: getACMEServers,
    retry: retryUnlessUnauthorized,
  });

  if (query.status == "pending") {
    return <Loading />;
  }
  if (query.status == "error") {
    return <Error msg={getErrorMessage(query.error)} />;
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

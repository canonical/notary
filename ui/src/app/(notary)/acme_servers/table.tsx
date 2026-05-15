import { Dispatch, SetStateAction } from "react";
import { ACMEServerEntry } from "@/types";
import {
  Button,
  MainTable,
  Panel,
  EmptyState,
  ContextualMenu,
} from "@canonical/react-components";
import {
  deleteACMEServer,
  setActiveACMEServer,
} from "@/queries";
import { useAuth } from "@/hooks/useAuth";
import { RoleID } from "@/types";
import {
  NotaryConfirmationModalData,
  NotaryConfirmationModal,
} from "@/components/NotaryConfirmationModal";
import { useState } from "react";

type TableProps = {
  servers: ACMEServerEntry[];
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
  onEdit: (server: ACMEServerEntry) => void;
};

export default function ACMEServersTable({
  servers,
  setAsideOpen,
  onEdit,
}: TableProps) {
  const auth = useAuth();
  const [confirmationModalData, setConfirmationModalData] =
    // eslint-disable-next-line
    useState<NotaryConfirmationModalData<any> | null>(null);

  const canManage = [RoleID.Admin, RoleID.CertificateManager].includes(
    auth.user?.role_id as RoleID,
  );

  const handleSetActive = (server: ACMEServerEntry) => {
    setConfirmationModalData({
      queryFn: setActiveACMEServer,
      queryParams: { id: server.id.toString() },
      queryKey: "acme_servers",
      closeFn: () => setConfirmationModalData(null),
      buttonConfirmText: "Set Active",
      warningText: `"${server.name}" will become the active ACME server. Any ongoing signing requests using a different server will continue until complete.`,
      successTitle: "Active ACME server updated",
      successMessage: `"${server.name}" is now the active ACME server.`,
      failureMessage: "Failed to set the active ACME server.",
    });
  };

  const handleDelete = (server: ACMEServerEntry) => {
    setConfirmationModalData({
      queryFn: deleteACMEServer,
      queryParams: { id: server.id.toString() },
      queryKey: "acme_servers",
      closeFn: () => setConfirmationModalData(null),
      buttonConfirmText: "Delete",
      warningText: `Deleting "${server.name}" will remove its configuration permanently. This action cannot be undone.`,
      successTitle: "ACME server deleted",
      successMessage: `"${server.name}" was deleted successfully.`,
      failureMessage: "Failed to delete the ACME server.",
    });
  };

  const rows = servers.map((server) => ({
    sortData: {
      id: server.id,
      name: server.name,
      dns_provider: server.dns_provider,
      active: server.active,
    },
    columns: [
      { content: server.id.toString() },
      { content: server.name },
      { content: server.directory_url },
      { content: server.dns_provider },
      {
        content: server.active ? (
          <span style={{ color: "rgba(14, 132, 32, 1)" }}>● Active</span>
        ) : (
          "Inactive"
        ),
      },
      {
        content: (
          <>
            {canManage && (
              <ContextualMenu hasToggleIcon position="right">
                <span className="p-contextual-menu__group">
                  {!server.active && (
                    <Button
                      className="p-contextual-menu__link"
                      onClick={() => handleSetActive(server)}
                    >
                      Set as Active
                    </Button>
                  )}
                  <Button
                    className="p-contextual-menu__link"
                    onClick={() => onEdit(server)}
                  >
                    Edit
                  </Button>
                  <Button
                    className="p-contextual-menu__link"
                    onClick={() => handleDelete(server)}
                  >
                    Delete
                  </Button>
                </span>
              </ContextualMenu>
            )}
          </>
        ),
        className: "u-align--right has-overflow",
        style: { height: "58px", overflow: "hidden" },
      },
    ],
  }));

  return (
    <Panel
      stickyHeader
      title="ACME Servers"
      className="u-fixed-width"
      controls={
        canManage && (
          <Button appearance="positive" onClick={() => setAsideOpen(true)}>
            Add ACME Server
          </Button>
        )
      }
    >
      <MainTable
        emptyStateMsg={<ACMEEmptyState setAsideOpen={setAsideOpen} />}
        sortable
        headers={[
          { content: "ID", sortKey: "id" },
          { content: "Name", sortKey: "name" },
          { content: "Directory URL" },
          { content: "DNS Provider", sortKey: "dns_provider" },
          { content: "Status", sortKey: "active" },
          { content: "Actions", className: "u-align--right has-overflow" },
        ]}
        rows={rows}
      />
      {confirmationModalData && (
        <NotaryConfirmationModal {...confirmationModalData} />
      )}
    </Panel>
  );
}

function ACMEEmptyState({
  setAsideOpen,
}: {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
}) {
  const auth = useAuth();
  const canManage = [RoleID.Admin, RoleID.CertificateManager].includes(
    auth.user?.role_id as RoleID,
  );

  return (
    <EmptyState image={""} title="No ACME Servers configured yet.">
      <p>
        Add an ACME server to enable signing certificate requests via ACME DNS
        challenge.
      </p>
      {canManage && (
        <Button
          appearance="positive"
          aria-label="add-acme-server-button"
          onClick={() => setAsideOpen(true)}
        >
          Add ACME Server
        </Button>
      )}
    </EmptyState>
  );
}

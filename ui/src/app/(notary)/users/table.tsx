import { useState, Dispatch, SetStateAction } from "react";
import { AsideFormData, UserEntry, RoleID } from "@/types";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  ContextualMenu,
  MainTable,
  Panel,
} from "@canonical/react-components";
import {
  ConfirmationModalData,
  UsersConfirmationModal,
  ChangePasswordModalData,
  ChangePasswordModal,
} from "./components";
import { useAuth } from "@/hooks/useAuth";
import { deleteUser } from "@/queries";

type TableProps = {
  users: UserEntry[];
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
  setFormData: Dispatch<SetStateAction<AsideFormData>>;
};

const roleLabels: Record<RoleID, string> = {
  [RoleID.Admin]: "Admin",
  [RoleID.CertificateManager]: "Certificate Manager",
  [RoleID.CertificateRequestor]: "Certificate Requestor",
  [RoleID.ReadOnly]: "Read Only",
};

export function UsersTable({ users, setAsideOpen, setFormData }: TableProps) {
  const auth = useAuth();
  const [confirmationModalData, setConfirmationModalData] =
    useState<ConfirmationModalData>(null);
  const [changePasswordModalData, setChangePasswordModalData] =
    useState<ChangePasswordModalData>(null);
  const queryClient = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });
  const handleDelete = (id: string, username: string) => {
    setConfirmationModalData({
      warningText: `Deleting user: "${username}". This action cannot be undone.`,
      onMouseDownFunc: () => {
        const authToken = auth.user ? auth.user.authToken : "";
        deleteMutation.mutate({ id: id, authToken });
      },
    });
  };
  const handleChangePassword = (id: string, username: string) => {
    setChangePasswordModalData({ id: id, username: username, self: false });
  };

  return (
    <Panel
      stickyHeader
      title="Users"
      className="u-fixed-width"
      controls={
        users.length > 0 && (
          <Button
            appearance="positive"
            onClick={() => {
              setFormData({ formTitle: "Add a New User" });
              setAsideOpen(true);
            }}
          >
            Create New User
          </Button>
        )
      }
    >
      <div>
        <MainTable
          headers={[
            {
              content: "ID",
            },
            {
              content: "Username",
            },
            {
              content: "Role",
            },
            {
              content: "Actions",
              className: "u-align--right has-overflow",
            },
          ]}
          rows={users.map((user) => ({
            columns: [
              {
                content: user.id.toString(),
              },
              {
                content: user.username,
              },
              {
                content: roleLabels[user.role_id],
              },
              {
                content: (
                  <ContextualMenu
                    links={[
                      {
                        children: "Delete User",
                        disabled: user.id === 1,
                        onClick: () =>
                          handleDelete(user.id.toString(), user.username),
                      },
                      {
                        children: "Change Password",
                        onClick: () =>
                          handleChangePassword(
                            user.id.toString(),
                            user.username,
                          ),
                      },
                    ]}
                    hasToggleIcon
                    position="right"
                    style={{ height: "40px" }}
                  />
                ),
                className: "u-align--right",
                hasOverflow: true,
              },
            ],
          }))}
        />
      </div>
      {confirmationModalData && (
        <UsersConfirmationModal
          modalData={confirmationModalData}
          setModalData={setConfirmationModalData}
        />
      )}
      {changePasswordModalData && (
        <ChangePasswordModal
          id={changePasswordModalData.id}
          username={changePasswordModalData.username}
          setChangePasswordModalVisible={() => setChangePasswordModalData(null)}
          self={false}
        />
      )}
    </Panel>
  );
}

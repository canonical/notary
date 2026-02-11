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
  ChangeRoleModal,
} from "./components";
import { deleteUser, updateUserRole } from "@/queries";

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
  const [confirmationModalData, setConfirmationModalData] =
    useState<ConfirmationModalData>(null);
  const [changePasswordModalData, setChangePasswordModalData] =
    useState<ChangePasswordModalData>(null);
  const [changeRoleModalData, setChangeRoleModalData] = useState<{
    id: string;
    email: string;
    role_id: RoleID;
  } | null>(null);
  const queryClient = useQueryClient();
  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });
  const handleDelete = (id: string, email: string) => {
    setConfirmationModalData({
      warningText: `Deleting user: "${email}". This action cannot be undone.`,
      onMouseDownFunc: () => {
        deleteMutation.mutate({ id: id });
      },
    });
  };
  const handleChangePassword = (id: string, email: string) => {
    setChangePasswordModalData({ id: id, email: email, self: false });
  };

  const updateRoleMutation = useMutation({
    mutationFn: updateUserRole,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const handleChangeRole = (id: string, email: string, role_id: RoleID) => {
    setChangeRoleModalData({ id, email, role_id });
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
              content: "Email",
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
                content: user.email,
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
                          handleDelete(user.id.toString(), user.email),
                      },
                      {
                        children: "Change Role",
                        disabled: user.id === 1,
                        onClick: () =>
                          handleChangeRole(
                            user.id.toString(),
                            user.email,
                            user.role_id,
                          ),
                      },
                      {
                        children: "Change Password",
                        onClick: () =>
                          handleChangePassword(user.id.toString(), user.email),
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
          email={changePasswordModalData.email}
          setChangePasswordModalVisible={() => setChangePasswordModalData(null)}
          self={false}
        />
      )}
      {changeRoleModalData && (
        <ChangeRoleModal
          email={changeRoleModalData.email}
          currentRoleID={changeRoleModalData.role_id}
          setChangeRoleModalVisible={() => setChangeRoleModalData(null)}
          onSubmit={(roleID) => {
            updateRoleMutation.mutate({
              id: changeRoleModalData.id,
              role_id: roleID,
            });
            setChangeRoleModalData(null);
          }}
        />
      )}
    </Panel>
  );
}

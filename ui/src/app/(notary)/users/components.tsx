import {
  Dispatch,
  SetStateAction,
  useState,
  ChangeEvent,
  createContext,
} from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changePassword, changeSelfPassword } from "@/queries";
import { passwordIsValid } from "@/utils";
import {
  ConfirmationModal,
  Modal,
  Button,
  Input,
  PasswordToggle,
  Form,
} from "@canonical/react-components";

export type ConfirmationModalData = {
  onMouseDownFunc: () => void;
  warningText: string;
} | null;

interface ConfirmationModalProps {
  modalData: ConfirmationModalData;
  setModalData: Dispatch<SetStateAction<ConfirmationModalData>>;
}

export type ChangePasswordModalData = {
  id: string;
  email: string;
  self: boolean;
} | null;

interface ChangePasswordModalProps {
  modalData: ChangePasswordModalData;
  setModalData: Dispatch<SetStateAction<ChangePasswordModalData>>;
}

export const ChangePasswordModalContext =
  createContext<ChangePasswordModalProps>({
    modalData: null,
    setModalData: () => {},
  });

export function UsersConfirmationModal({
  modalData,
  setModalData,
}: ConfirmationModalProps) {
  const confirmQuery = () => {
    modalData?.onMouseDownFunc();
    setModalData(null);
  };
  return (
    <ConfirmationModal
      title="Confirm Action"
      confirmButtonLabel="Delete"
      onConfirm={confirmQuery}
      close={() => setModalData(null)}
    >
      <p>{modalData?.warningText}</p>
    </ConfirmationModal>
  );
}

export function ChangePasswordModal({
  id,
  email,
  self,
  setChangePasswordModalVisible,
}: {
  id: string;
  email: string;
  self: boolean;
  setChangePasswordModalVisible: Dispatch<SetStateAction<boolean>>;
}) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: self ? changeSelfPassword : changePassword,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setErrorText("");
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });

  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const [, setErrorText] = useState<string>("");

  const passwordsMatch = password1 === password2;
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword1(event.target.value);
  };
  const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword2(event.target.value);
  };

  return (
    <Modal
      title="Change Password"
      buttonRow={
        <>
          <Button onClick={() => setChangePasswordModalVisible(false)}>
            Cancel
          </Button>
          <Button
            appearance="positive"
            disabled={!passwordsMatch || !passwordIsValid(password1)}
            onClick={(event) => {
              event.preventDefault();
              mutation.mutate({
                id,
                password: password1,
              });
            }}
          >
            Submit
          </Button>
        </>
      }
    >
      <Form>
        <Input
          id="InputEmail"
          label="Email"
          type="text"
          required={true}
          disabled={true}
          value={email}
        />
        <PasswordToggle
          help="Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
          id="password1"
          label="New Password"
          required={true}
          onChange={handlePassword1Change}
          error={password1Error}
        />
        <PasswordToggle
          id="password2"
          label="Confirm New Password"
          required={true}
          onChange={handlePassword2Change}
          error={password2Error}
        />
      </Form>
    </Modal>
  );
}

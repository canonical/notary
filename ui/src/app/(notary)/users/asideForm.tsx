import { useMutation, useQueryClient } from "@tanstack/react-query";
import { passwordIsValid } from "@/utils";
import { changePassword, postUser } from "@/queries";
import { ChangeEvent, Dispatch, SetStateAction, useState } from "react";
import {
  Panel,
  Button,
  Input,
  PasswordToggle,
  Select,
  Form,
  Notification,
  useToastNotification,
} from "@canonical/react-components";
import { AsideFormData, RoleID, getErrorMessage } from "@/types";
import { z } from "zod";

type AsideProps = {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
  formData: AsideFormData;
};

export default function UsersPageAsidePanel(asideProps: AsideProps) {
  return (
    <Panel
      title={asideProps.formData.formTitle}
      controls={
        <Button onClick={() => asideProps.setAsideOpen(false)} hasIcon>
          <i className="p-icon--close" />
        </Button>
      }
    >
      {asideProps.formData.formTitle == "Add a New User" && (
        <AddNewUserForm {...asideProps} />
      )}
      {asideProps.formData.formTitle == "Change User Password" && (
        <ChangePasswordForm {...asideProps} />
      )}
    </Panel>
  );
}

function AddNewUserForm(asideProps: AsideProps) {
  const queryClient = useQueryClient();
  const toastNotify = useToastNotification();
  const mutation = useMutation({
    mutationFn: postUser,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setEmail("");
      setRoleID(RoleID.Admin);
      setPassword1("");
      setPassword2("");
      setErrorText("");
      asideProps.setAsideOpen(false);
      toastNotify.success(
        "The user was created successfully.",
        undefined,
        "User created",
      );
    },
    onError: (e: Error) => {
      setErrorText(getErrorMessage(e));
      toastNotify.failure(
        "User creation failed",
        e,
        "Failed to create the user.",
      );
    },
  });
  const [email, setEmail] = useState<string>("");
  const [role_id, setRoleID] = useState<number>(RoleID.Admin);
  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const passwordsMatch = password1 === password2;
  const emailSchema = z.string().email();
  const isEmailValid = emailSchema.safeParse(email).success;
  const emailError = email && !isEmailValid ? "Email is not valid" : "";
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const [errorText, setErrorText] = useState<string>("");
  const handleEmailChange = (event: ChangeEvent<HTMLInputElement>) => {
    setEmail(event.target.value);
  };
  const handleRoleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    setRoleID(Number(event.target.value));
  };
  const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword1(event.target.value);
  };
  const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword2(event.target.value);
  };
  return (
    <Form>
      <div className="p-form__group row">
        <Input
          id="InputEmail"
          label="Email"
          type="text"
          required={true}
          value={email}
          onChange={handleEmailChange}
          error={emailError}
        />
        <Select
          id="roleID"
          label="Role"
          value={role_id.toString()}
          onChange={handleRoleChange}
          options={[
            {
              disabled: true,
              label: "Select an option",
              value: "",
            },
            {
              label: "Admin",
              value: RoleID.Admin,
            },
            {
              label: "Certificate Manager",
              value: RoleID.CertificateManager,
            },
            {
              label: "Certificate Requestor",
              value: RoleID.CertificateRequestor,
            },
            {
              label: "Read Only",
              value: RoleID.ReadOnly,
            },
          ]}
        />
        <PasswordToggle
          help="Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
          id="password1"
          label="Password"
          value={password1}
          onChange={handlePassword1Change}
          required={true}
          error={password1Error}
        />
        <PasswordToggle
          id="password2"
          label="Confirm Password"
          value={password2}
          onChange={handlePassword2Change}
          required={true}
          error={password2Error}
        />
        {errorText && (
          <Notification severity="negative" title="Error">
            {errorText}
          </Notification>
        )}
        <Button
          appearance="positive"
          disabled={
            !passwordsMatch || !passwordIsValid(password1) || !isEmailValid
          }
          onClick={(event) => {
            event.preventDefault();
            mutation.mutate({
              email: email,
              password: password1,
              role_id: role_id,
            });
          }}
        >
          Submit
        </Button>
      </div>
    </Form>
  );
}

function ChangePasswordForm(asideProps: AsideProps) {
  const queryClient = useQueryClient();
  const toastNotify = useToastNotification();
  const mutation = useMutation({
    mutationFn: changePassword,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setErrorText("");
      asideProps.setAsideOpen(false);
      toastNotify.success(
        "The user's password was updated successfully.",
        undefined,
        "Password updated",
      );
    },
    onError: (e: Error) => {
      setErrorText(getErrorMessage(e));
      toastNotify.failure(
        "Password update failed",
        e,
        "Failed to update the user's password.",
      );
    },
  });
  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const passwordsMatch = password1 === password2;
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const [errorText, setErrorText] = useState<string>("");
  const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword1(event.target.value);
  };
  const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword2(event.target.value);
  };
  return (
    <Form>
      <div className="p-form__group row">
        <Input
          id="InputEmail"
          label="Email"
          type="text"
          value={asideProps.formData.user?.email}
          disabled={true}
        />
        <PasswordToggle
          help="Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
          id="password1"
          label="Password"
          onChange={handlePassword1Change}
          required={true}
          error={password1Error}
        />
        <PasswordToggle
          id="password2"
          label="Password"
          onChange={handlePassword2Change}
          required={true}
          error={password2Error}
        />
        {errorText && (
          <Notification severity="negative" title="Error">
            {errorText}
          </Notification>
        )}
        <Button
          appearance="positive"
          disabled={!passwordsMatch || !passwordIsValid(password1)}
          onClick={(event) => {
            event.preventDefault();
            mutation.mutate({
              id: asideProps.formData.user ? asideProps.formData.user.id : "0",
              password: password1,
            });
          }}
        >
          Submit
        </Button>
      </div>
    </Form>
  );
}

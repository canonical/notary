import { useMutation, useQueryClient } from "@tanstack/react-query";
import { passwordIsValid } from "@/utils";
import { changePassword, postUser } from "@/queries";
import { ChangeEvent, Dispatch, SetStateAction, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import {
  Panel,
  Button,
  Input,
  PasswordToggle,
  Select,
  Form,
} from "@canonical/react-components";
import { AsideFormData, RoleID } from "@/types";

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
  const auth = useAuth();
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: postUser,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setErrorText("");
      asideProps.setAsideOpen(false);
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });
  const [email, setEmail] = useState<string>("");
  const [role_id, setRoleID] = useState<number>(RoleID.Admin);
  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const passwordsMatch = password1 === password2;
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const [, setErrorText] = useState<string>("");
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
          onChange={handleEmailChange}
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
        <Button
          appearance="positive"
          disabled={!passwordsMatch || !passwordIsValid(password1)}
          onClick={(event) => {
            event.preventDefault();
            mutation.mutate({
              authToken: auth.user ? auth.user.authToken : "",
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
  const auth = useAuth();
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: changePassword,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setErrorText("");
      asideProps.setAsideOpen(false);
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });
  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const passwordsMatch = password1 === password2;
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const [, setErrorText] = useState<string>("");
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
        <Button
          appearance="positive"
          disabled={!passwordsMatch || !passwordIsValid(password1)}
          onClick={(event) => {
            event.preventDefault();
            mutation.mutate({
              authToken: auth.user ? auth.user.authToken : "",
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

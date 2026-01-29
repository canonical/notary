"use client";

import { passwordIsValid } from "@/utils";
import { login, postFirstUser } from "@/queries";
import {
  Input,
  PasswordToggle,
  Button,
  Form,
  LoginPageLayout,
} from "@canonical/react-components";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, ChangeEvent } from "react";
import { RoleID } from "@/types";
import { z } from "zod";

export default function Initialize() {
  const queryClient = useQueryClient();
  const loginMutation = useMutation({
    mutationFn: login,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["user"] }),
        queryClient.invalidateQueries({ queryKey: ["status"] }),
      ]);
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });
  const postUserMutation = useMutation({
    mutationFn: postFirstUser,
    onSuccess: () => {
      setErrorText("");
      loginMutation.mutate({ email: email, password: password1 });
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });
  const [email, setEmail] = useState<string>("");
  const [password1, setPassword1] = useState<string>("");
  const [password2, setPassword2] = useState<string>("");
  const passwordsMatch = password1 === password2;
  const emailSchema = z.email();
  const isEmailValid = emailSchema.safeParse(email).success;
  const emailError = email && !isEmailValid ? "Email is not valid" : "";
  const password1Error =
    password1 && !passwordIsValid(password1) ? "Password is not valid" : "";
  const password2Error =
    password2 && !passwordsMatch ? "Passwords do not match" : "";

  const [, setErrorText] = useState<string>("");
  const handleEmailChange = (event: ChangeEvent<HTMLInputElement>) => {
    setEmail(event.target.value);
  };
  const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword1(event.target.value);
  };
  const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword2(event.target.value);
  };
  return (
    <>
      <LoginPageLayout
        logo={{
          src: "https://assets.ubuntu.com/v1/82818827-CoF_white.svg",
          title: "Notary",
          url: "#",
        }}
        title="Initialize Notary"
      >
        <Form>
          <h4>Create the initial admin user</h4>
          <Input
            id="InputEmail"
            label="Email"
            type="text"
            required={true}
            onChange={handleEmailChange}
            error={emailError}
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
            label="Confirm Password"
            onChange={handlePassword2Change}
            required={true}
            error={password2Error}
          />
          <Button
            appearance="positive"
            disabled={
              !passwordsMatch || !passwordIsValid(password1) || !isEmailValid
            }
            onClick={(event) => {
              event.preventDefault();
              if (passwordsMatch && passwordIsValid(password1)) {
                postUserMutation.mutate({
                  email: email,
                  password: password1,
                  role_id: RoleID.Admin,
                });
              }
            }}
          >
            Submit
          </Button>
        </Form>
      </LoginPageLayout>
    </>
  );
}

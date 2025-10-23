"use client";

import { login } from "@/queries";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, ChangeEvent } from "react";
import {
  Input,
  PasswordToggle,
  Button,
  Form,
  Notification,
  LoginPageLayout,
} from "@canonical/react-components";

export default function LoginPage() {
  const queryClient = useQueryClient();
  const loginMutation = useMutation({
    mutationFn: login,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["user"] });
    },
    onError: (e: Error) => {
      setErrorText(e.message);
    },
  });

  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [errorText, setErrorText] = useState<string>("");
  const handleEmailChange = (event: ChangeEvent<HTMLInputElement>) => {
    setEmail(event.target.value);
  };
  const handlePasswordChange = (event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  };
  return (
    <>
      <LoginPageLayout
        logo={{
          src: "https://assets.ubuntu.com/v1/82818827-CoF_white.svg",
          title: "Notary",
          url: "#",
        }}
        title="Log in"
      >
        <Form>
          <Input
            id="InputEmail"
            label="Email"
            type="text"
            required={true}
            onChange={handleEmailChange}
          />
          <PasswordToggle
            id="InputPassword"
            label="Password"
            required={true}
            onChange={handlePasswordChange}
          />
          {errorText && (
            <Notification severity="negative" title="Error">
              {errorText.split("error: ")}
            </Notification>
          )}
          <Button
            appearance="positive"
            disabled={password.length == 0 || email.length == 0}
            onClick={(event) => {
              event.preventDefault();
              loginMutation.mutate({ email: email, password: password });
            }}
          >
            Log In
          </Button>
          <Button
            appearance="positive"
            onClick={(event) => {
              event.preventDefault();
              window.location.href = "/api/v1/oauth/login";
            }}
          >
            Log In with OIDC
          </Button>
        </Form>
      </LoginPageLayout>
    </>
  );
}

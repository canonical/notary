"use client"

import { getStatus, login } from "@/queries"
import { useMutation, useQuery } from "@tanstack/react-query"
import { useState, ChangeEvent } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/hooks/useAuth"
import { statusResponse } from "@/types"
import { Input, PasswordToggle, Button, Form, Notification, LoginPageLayout } from "@canonical/react-components";


export default function LoginPage() {
    const router = useRouter()
    const auth = useAuth()
    const statusQuery = useQuery<statusResponse, Error>({
        queryKey: ["status"],
        queryFn: () => getStatus(),
        enabled: auth.firstUserInitialized == "unknown"
    })
    if (auth.firstUserInitialized == "unknown" && statusQuery.data) {
        auth.setFirstUserInitialized(statusQuery.data.initialized)
    }
    const mutation = useMutation({
        mutationFn: login,
        onSuccess: (result) => {
            setErrorText("")
            auth.login(result?.token)
            router.push('/')
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })

    const [username, setUsername] = useState<string>("")
    const [password, setPassword] = useState<string>("")
    const [errorText, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePasswordChange = (event: ChangeEvent<HTMLInputElement>) => { setPassword(event.target.value) }
    return (
        <LoginPageLayout
            logo={{
                src: 'https://assets.ubuntu.com/v1/82818827-CoF_white.svg',
                title: 'Notary',
                url: '#'
            }}
            title="Log in"
        >
            <Form>
                <Input
                    id="InputUsername"
                    label="Username"
                    type="text"
                    required={true}
                    onChange={handleUsernameChange}
                />
                <PasswordToggle
                    id="InputPassword"
                    label="Password"
                    required={true}
                    onChange={handlePasswordChange}
                />
                {errorText &&
                    <Notification
                        severity="negative"
                        title="Error"
                    >
                        {errorText.split("error: ")}
                    </Notification>
                }
                <Button
                    appearance="positive"
                    disabled={password.length == 0 || username.length == 0}
                    onClick={
                        (event) => {
                            event.preventDefault();
                            mutation.mutate({ username: username, password: password })
                        }
                    }
                >
                    Log In
                </Button>
            </Form>
        </LoginPageLayout>
    )
}
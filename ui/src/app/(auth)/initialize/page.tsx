"use client"

import { passwordIsValid } from "@/utils"
import { getStatus, login, postFirstUser } from "@/queries"
import { useAuth } from "@/hooks/useAuth"
import { Input, PasswordToggle, Button, Form, LoginPageLayout } from "@canonical/react-components";
import { useMutation, useQuery } from "@tanstack/react-query"
import { useState, ChangeEvent } from "react"
import { useRouter } from "next/navigation"
import { useCookies } from "react-cookie"


export default function Initialize() {
    const router = useRouter()
    const auth = useAuth()
    const [, setCookie] = useCookies(['user_token']);
    const statusQuery = useQuery({
        queryKey: ["status"],
        queryFn: () => getStatus(),
    })
    if (statusQuery.data && statusQuery.data.initialized) {
        auth.setFirstUserCreated(true)
        router.push("/login")
    }
    const loginMutation = useMutation({
        mutationFn: login,
        onSuccess: (result) => {
            setErrorText("")
            setCookie('user_token', result.token, {
                sameSite: true,
                secure: true,
                expires: new Date(new Date().getTime() + 60 * 60 * 1000),
            })
            router.push('/certificate_requests')
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const postUserMutation = useMutation({
        mutationFn: postFirstUser,
        onSuccess: () => {
            setErrorText("")
            auth.setFirstUserCreated(true)
            loginMutation.mutate({ username: username, password: password1 })
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [username, setUsername] = useState<string>("")
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const password1Error = password1 && !passwordIsValid(password1) ? "Password is not valid" : ""
    const password2Error = password2 && !passwordsMatch ? "Passwords do not match" : ""

    const [, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <>
            <LoginPageLayout
                logo={{
                    src: 'https://assets.ubuntu.com/v1/82818827-CoF_white.svg',
                    title: 'Notary',
                    url: '#'
                }}
                title="Initialize Notary"
            >
                <Form>
                    <h4>Create the initial admin user</h4>
                    <Input
                        id="InputUsername"
                        label="Username"
                        type="text"
                        required={true}
                        onChange={handleUsernameChange}
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
                        disabled={!passwordsMatch || !passwordIsValid(password1)}
                        onClick={(event) => {
                            event.preventDefault();
                            if (passwordsMatch && passwordIsValid(password1)) {
                                postUserMutation.mutate({ username: username, password: password1 });
                            }
                        }}
                    >
                        Submit
                    </Button>
                </Form>
            </LoginPageLayout>
        </>
    )
}

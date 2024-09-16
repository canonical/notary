"use client"

import { getStatus, login } from "../queries"
import { useMutation, useQuery } from "react-query"
import { useState, ChangeEvent } from "react"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"
import { useAuth } from "../auth/authContext"
import { statusResponse } from "../types"
import { Navigation, Theme, Input, PasswordToggle, Button, Form, Notification } from "@canonical/react-components";


export default function LoginPage() {
    const router = useRouter()
    const auth = useAuth()
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const statusQuery = useQuery<statusResponse, Error>({
        queryFn: () => getStatus()
    })
    if (!auth.firstUserCreated && (statusQuery.data && !statusQuery.data.initialized)) {
        router.push("/initialize")
    }
    const mutation = useMutation(login, {
        onSuccess: (e) => {
            setErrorText("")
            setCookie('user_token', e, {
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

    const [username, setUsername] = useState<string>("")
    const [password, setPassword] = useState<string>("")
    const [errorText, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePasswordChange = (event: ChangeEvent<HTMLInputElement>) => { setPassword(event.target.value) }
    return (
        <>
            <Navigation
                items={[]}
                logo={{
                    src: 'https://assets.ubuntu.com/v1/82818827-CoF_white.svg',
                    title: 'Notary',
                    url: '#'
                }}
                theme={Theme.DARK}
            />
            <div style={{
                display: "flex",
                alignContent: "center",
                justifyContent: "center",
                flexWrap: "wrap",
                height: "93.5vh",
            }}>
                <div className="p-panel" style={{
                    width: "35rem",
                    minWidth: "min-content",
                    minHeight: "min-content",
                }}>
                    <div className="p-panel__content">
                        <div className="u-fixed-width">
                            <Form>
                                <fieldset>
                                    <h2 className="p-panel__title">Login</h2>
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
                                </fieldset>
                            </Form>
                        </div>
                    </div>
                </div >
            </div >
        </>
    )
}
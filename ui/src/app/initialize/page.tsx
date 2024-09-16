"use client"

import { useState, ChangeEvent } from "react"
import { getStatus, login, postFirstUser } from "../queries"
import { useMutation, useQuery } from "react-query"
import { useRouter } from "next/navigation"
import { passwordIsValid } from "../utils"
import { useAuth } from "../auth/authContext"
import { Logo } from "../nav"
import { useCookies } from "react-cookie"
import { statusResponse } from "../types"
import { Navigation, Theme, Input, PasswordToggle, Button, Form } from "@canonical/react-components";


export default function Initialize() {
    const router = useRouter()
    const auth = useAuth()
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const statusQuery = useQuery<statusResponse, Error>({
        queryFn: () => getStatus()
    })
    if (statusQuery.data && statusQuery.data.initialized) {
        auth.setFirstUserCreated(true)
        router.push("/login")
    }
    const loginMutation = useMutation(login, {
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
    const postUserMutation = useMutation(postFirstUser, {
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

    const [errorText, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <>
            <Navigation
                items={[]}
                logo={< Logo />}
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
                    width: "45rem",
                    minWidth: "min-content",
                    minHeight: "min-content",
                }}>
                    <fieldset>
                        <div className="p-panel__header">
                            <h2>Initialize Notary</h2>
                        </div>
                        <div className="p-panel__content">
                            <Form>
                                <h4>Create the initial admin user</h4>
                                <Input
                                    id="InputUsername"
                                    label="Username"
                                    type="text"
                                    onChange={handleUsernameChange}
                                />
                                <PasswordToggle
                                    help="Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol."
                                    id="password1"
                                    label="Password"
                                    onChange={handlePassword1Change}
                                    error={password1Error}
                                />
                                <PasswordToggle
                                    id="password2"
                                    label="Confirm Password"
                                    onChange={handlePassword2Change}
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
                        </div>
                    </fieldset>
                </div >
            </div >
        </>
    )
}

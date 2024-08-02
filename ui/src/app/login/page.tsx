"use client"

import { getStatus, login } from "../queries"
import { useMutation, useQuery } from "react-query"
import { useState, ChangeEvent } from "react"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"
import { useAuth } from "../auth/authContext"
import { statusResponse } from "../types"
import { Logo } from "../nav"


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
            <div style={{ backgroundColor: "#262626", height: "7.5vh" }}>
                <div style={{ marginLeft: "30px" }}>
                    <Logo />
                </div>
            </div>
            <div style={{
                display: "flex",
                alignContent: "center",
                justifyContent: "center",
                flexWrap: "wrap",
                height: "92.5vh",
            }}>
                <div className="p-panel" style={{
                    width: "35rem",
                    minWidth: "min-content",
                    minHeight: "min-content",
                }}>
                    <div className="p-panel__content">
                        <div className="u-fixed-width">
                            <form className="p-form">
                                <fieldset>
                                    <h2 className="p-panel__title">Login</h2>
                                    <label htmlFor="InputUsername">Username</label>
                                    <input type="text" id="InputUsername" name="InputUsername" onChange={handleUsernameChange} />
                                    <label htmlFor="InputPassword">Password</label>
                                    <input type="password" id="InputPassword" name="InputPassword" placeholder="******" autoComplete="current-password" onChange={handlePasswordChange} />
                                    {errorText &&
                                        <div className="p-notification--negative">
                                            <div className="p-notification__content">
                                                <h5 className="p-notification__title">Error</h5>
                                                <p className="p-notification__message">{errorText.split("error: ")}</p>
                                            </div>
                                        </div>
                                    }
                                    {password.length != 0 && username.length != 0 ? (
                                        <button className="p-button--positive" type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ username: username, password: password }) }}>Log In</button>
                                    ) : (
                                        <button disabled={true} className="p-button--positive" type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ username: username, password: password }) }}>Log In</button>
                                    )}
                                </fieldset>
                            </form>
                        </div>
                    </div>
                </div >
            </div >
        </>
    )
}
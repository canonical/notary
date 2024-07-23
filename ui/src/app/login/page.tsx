"use client"

import { login } from "../queries"
import { useMutation } from "react-query"
import { useState, ChangeEvent } from "react"
import { useCookies } from "react-cookie"
import { useRouter } from "next/navigation"

export default function LoginPage() {
    const router = useRouter()
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
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
        <div style={{
            display: "flex",
            alignContent: "center",
            justifyContent: "center",
            flexWrap: "wrap",
            height: "100vh",
        }}>
            <div className="p-panel" style={{
                width: "25rem",
                minWidth: "min-content",
                minHeight: "min-content",
            }}>
                <div className="p-panel__header is-sticky">
                    <h4 className="p-panel__title">Login</h4>
                </div>
                <div className="p-panel__content">
                    <div className="u-fixed-width">
                        <form>
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
                            <button type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ username: username, password: password }) }}>Submit</button>
                        </form>
                    </div>
                </div>
            </div >
        </div >
    )
}
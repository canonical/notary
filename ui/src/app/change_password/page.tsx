"use client"

import { changePassword } from "../queries"
import { useMutation } from "react-query"
import { useState, ChangeEvent } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "../auth/authContext"

export default function ChangePasswordPage() {
    const router = useRouter()
    const auth = useAuth()
    if (!auth.user) {
        router.push('/login')
    }

    const mutation = useMutation(changePassword, {
        onSuccess: (e) => {
            setErrorText("")
            router.push('/certificate_requests')
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })

    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const [errorText, setErrorText] = useState<string>("")
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <div style={{
            display: "flex",
            alignContent: "center",
            justifyContent: "center",
            flexWrap: "wrap",
            height: "100vh",
        }}>
            <div className="p-panel" style={{
                width: "45rem",
                minWidth: "min-content",
                minHeight: "min-content",
            }}>
                <div className="p-panel__header is-sticky">
                    <h4 className="p-panel__title">Change Password</h4>
                </div>
                <div className="p-panel__content">
                    <div className="u-fixed-width">
                        <form className={"p-form-validation " + (!passwordsMatch ? "is-error" : "")}>
                            <label className="p-form__label">New Password</label>
                            <input className="p-form-validation__input" type="password" id="password1" name="password" placeholder="******" autoComplete="current-password" required={true} onChange={handlePassword1Change} />
                            <p className="p-form-help-text">
                                Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.
                            </p>
                            <label htmlFor="p-form__label">Confirm New Password</label>
                            <input className="p-form-validation__input" type="password" id="InputPassword" name="password2" placeholder="******" autoComplete="current-password" onChange={handlePassword2Change} />
                            {!passwordsMatch &&<p className="p-form-validation__message">Passwords do not match</p>}
                            {errorText &&
                                <div className="p-notification--negative">
                                    <div className="p-notification__content">
                                        <h5 className="p-notification__title">Error</h5>
                                        <p className="p-notification__message">{errorText.split("error: ")}</p>
                                    </div>
                                </div>
                            }
                            {!passwordsMatch ? (
                                <>
                                    <button type="submit" name="submit" disabled={true}>Submit</button>
                                </>
                            ) : (
                                <button type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ authToken: (auth.user ? auth.user.authToken : ""), username: (auth.user ? auth.user.username : ""), password: password1 }) }}>Submit</button>
                            )
                            }
                        </form>
                    </div>
                </div>
            </div >
        </div >
    )
}
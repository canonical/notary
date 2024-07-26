import { useMutation, useQueryClient } from "react-query";
import { extractCSR } from "../utils";
import { useCookies } from "react-cookie";
import { postUser } from "../queries";
import { ChangeEvent, useContext, useState } from "react";
import { AsideContext } from "../aside";
import { useAuth } from "../auth/authContext";

export default function UploadUserAsidePanel() {
    const asideContext = useContext(AsideContext)
    const auth = useAuth()
    const queryClient = useQueryClient()
    const mutation = useMutation(postUser, {
        onSuccess: () => {
            queryClient.invalidateQueries('users')
            setErrorText("")
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [username, setUsername] = useState<string>("")
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const [errorText, setErrorText] = useState<string>("")
    const handleUsernameChange = (event: ChangeEvent<HTMLInputElement>) => { setUsername(event.target.value) }
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <div className="p-panel" >
            <div className="p-panel__header">
                <h4 className="p-panel__title">Add a New User</h4>
                <div className="p-panel__controls">
                    <button onClick={() => asideContext.setIsOpen(false)} className="p-button--base u-no-margin--bottom has-icon"><i className="p-icon--close"></i></button>
                </div>
            </div>
            <div className="p-panel__content">
                <form className={"p-form-validation " + (!passwordsMatch ? "is-error" : "")}>
                    <div className="p-form__group row">
                        <label className="p-form__label">User Name</label>
                        <input type="text" id="InputUsername" name="InputUsername" onChange={handleUsernameChange} />
                        <label className="p-form__label">Password</label>
                        <input className="p-form-validation__input" type="password" id="password1" name="password" placeholder="******" autoComplete="current-password" required={true} onChange={handlePassword1Change} />
                        <p className="p-form-help-text">
                            Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.
                        </p>
                        <label htmlFor="p-form__label">Password Again</label>
                        <input className="p-form-validation__input" type="password" id="InputPassword" name="password2" placeholder="******" autoComplete="current-password" onChange={handlePassword2Change} />
                        {!passwordsMatch && <p className="p-form-validation__message">Passwords do not match</p>}
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
                            <button type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ authToken: (auth.user ? auth.user.authToken : ""), username: username, password: password1 }) }}>Submit</button>
                        )
                        }
                    </div>
                </form>
            </div>
        </div >
    )
}

// function SubmitUser({ csrText, onClickFunc }: { csrText: string, onClickFunc: any }) {
//     const validationComponent = csrText == "" ? <></> : csrIsValid ? <div><i className="p-icon--success"></i>Valid CSR</div> : <div><i className="p-icon--error"></i>Invalid CSR</div>
//     const buttonComponent = csrIsValid ? <button className="p-button--positive u-float-right" name="submit" onClick={onClickFunc} >Submit</button> : <button className="p-button--positive u-float-right" name="submit" disabled={true} onClick={onClickFunc} >Submit</button>
//     return (
//         <>
//             {validationComponent}
//             {buttonComponent}
//         </>
//     )
// }
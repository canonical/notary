import { Dispatch, SetStateAction, useState, ChangeEvent, createContext } from "react"
import { useAuth } from "../auth/authContext"
import { useMutation, useQueryClient } from "react-query"
import { changePassword } from "../queries"
import { passwordIsValid } from "../utils"

export type ConfirmationModalData = {
    onMouseDownFunc: () => void
    warningText: string
} | null

interface ConfirmationModalProps {
    modalData: ConfirmationModalData
    setModalData: Dispatch<SetStateAction<ConfirmationModalData>>
}

export type ChangePasswordModalData = {
    id: string
    username: string
} | null

interface ChangePasswordModalProps {
    modalData: ChangePasswordModalData
    setModalData: Dispatch<SetStateAction<ChangePasswordModalData>>
}

export const ChangePasswordModalContext = createContext<ChangePasswordModalProps>({
    modalData: null,
    setModalData: () => { }
})

export function ConfirmationModal({ modalData, setModalData }: ConfirmationModalProps) {
    const confirmQuery = () => {
        modalData?.onMouseDownFunc()
        setModalData(null)
    }
    return (
        <div className="p-modal" id="modal">
            <section className="p-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-description">
                <header className="p-modal__header">
                    <h2 className="p-modal__title" id="modal-title">Confirm Action</h2>
                </header>
                <p>{modalData?.warningText}</p>
                <footer className="p-modal__footer">
                    <button className="u-no-margin--bottom" aria-controls="modal" onMouseDown={() => setModalData(null)}>Cancel</button>
                    <button className="p-button--negative u-no-margin--bottom" onMouseDown={confirmQuery}>Confirm</button>
                </footer>
            </section>
        </div>
    )
}

export function ChangePasswordModal({ modalData, setModalData }: ChangePasswordModalProps) {
    const auth = useAuth()
    const queryClient = useQueryClient()
    const mutation = useMutation(changePassword, {
        onSuccess: () => {
            queryClient.invalidateQueries('users')
            setErrorText("")
            setModalData(null)
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [showPassword1, setShowPassword1] = useState<boolean>(false)
    const [password1, setPassword1] = useState<string>("")
    const [password2, setPassword2] = useState<string>("")
    const passwordsMatch = password1 === password2
    const [errorText, setErrorText] = useState<string>("")
    const handlePassword1Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword1(event.target.value) }
    const handlePassword2Change = (event: ChangeEvent<HTMLInputElement>) => { setPassword2(event.target.value) }
    return (
        <div className="p-modal" id="modal">
            <section className="p-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-description">
                <header className="p-modal__header">
                    <h2 className="p-modal__title" id="modal-title">Change Password</h2>
                </header>
                <form className={"p-form-validation " + ((!passwordIsValid(password1) && password1 != "") || (!passwordsMatch && password2 != "") ? "is-error" : "")}>
                    <div className="p-form__group row">
                        <label className="p-form__label">Username</label>
                        <input type="text" id="InputUsername" name="InputUsername" value={modalData?.username} disabled={true} />
                        <div>
                            <label className="p-form__label">New Password</label>
                            <button className="p-button--base u-no-margin--bottom has-icon" style={{ float: "right" }} aria-live="polite" aria-controls="password" onClick={(e) => { e.preventDefault(); setShowPassword1(!showPassword1) }}>
                                {showPassword1 ? (
                                    <>
                                        <span className="p-form-password-toggle__label">
                                            Hide
                                        </span>
                                        <i className="p-icon--hide"></i>
                                    </>
                                ) : (
                                    <>
                                        <span className="p-form-password-toggle__label">
                                            Show
                                        </span>
                                        <i className="p-icon--show"></i>
                                    </>
                                )}
                            </button>
                        </div>
                        <input className="p-form-validation__input" type={showPassword1 ? "text" : "password"} id="password1" name="password" placeholder="******" autoComplete="current-password" required={true} onChange={handlePassword1Change} />
                        <p className="p-form-help-text">
                            Password must have 8 or more characters, must include at least one capital letter, one lowercase letter, and either a number or a symbol.
                        </p>
                        <label htmlFor="p-form__label">Confirm New Password</label>
                        <input className="p-form-validation__input" type="password" id="InputPassword" name="password2" placeholder="******" autoComplete="current-password" onChange={handlePassword2Change} />
                        {!passwordIsValid(password1) && password1 != "" && <p className="p-form-validation__message">Password is not valid</p>}
                        {passwordIsValid(password1) && !passwordsMatch && password2 != "" && <p className="p-form-validation__message">Passwords do not match</p>}
                        {errorText &&
                            <div className="p-notification--negative">
                                <div className="p-notification__content">
                                    <h5 className="p-notification__title">Error</h5>
                                    <p className="p-notification__message">{errorText.split("error: ")}</p>
                                </div>
                            </div>
                        }

                    </div>
                </form>
                <footer className="p-modal__footer">
                    <button className="u-no-margin--bottom" aria-controls="modal" onMouseDown={() => setModalData(null)}>Cancel</button>
                    {!passwordsMatch || !passwordIsValid(password1) ? (
                        <button className="p-button--positive u-no-margin--bottom" type="submit" name="submit" disabled={true}>Submit</button>
                    ) : (
                        <button className="p-button--positive u-no-margin--bottom" type="submit" name="submit" onClick={(event) => { event.preventDefault(); mutation.mutate({ authToken: (auth.user ? auth.user.authToken : ""), id: modalData ? modalData.id : "", password: password1 }) }}>Submit</button>
                    )}
                </footer>
            </section>
        </div>
    )
}
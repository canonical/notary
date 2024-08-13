import { useMutation, useQueryClient } from "react-query";
import { extractCSR } from "../utils";
import { useCookies } from "react-cookie";
import { postCSR } from "../queries";
import { ChangeEvent, useContext, useState } from "react";
import { AsideContext } from "../aside";

export default function CertificateRequestsAsidePanel(): JSX.Element {
    const asideContext = useContext(AsideContext)
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const [errorText, setErrorText] = useState<string>("")
    const queryClient = useQueryClient()
    const mutation = useMutation(postCSR, {
        onSuccess: () => {
            setErrorText("")
            asideContext.setIsOpen(false)
            queryClient.invalidateQueries('csrs')
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [CSRPEMString, setCSRPEMString] = useState<string>("")
    const handleTextChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
        setCSRPEMString(event.target.value);
    }
    const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (file) {
            const reader = new FileReader();
            reader.onload = (e: ProgressEvent<FileReader>) => {
                if (e.target) {
                    if (e.target.result) {
                        setCSRPEMString(e.target.result.toString());
                    }
                }
            };
            reader.readAsText(file);
        }
    };
    return (
        <div className="p-panel" >
            <div className="p-panel__header">
                <h4 className="p-panel__title">Add a New Certificate Request</h4>
                <div className="p-panel__controls">
                    <button onClick={() => asideContext.setIsOpen(false)} className="p-button--base u-no-margin--bottom has-icon"><i className="p-icon--close"></i></button>
                </div>
            </div>
            <div className="p-panel__content">
                <form className="p-form p-form--stacked">
                    <div className="p-form__group row">
                        <label htmlFor="textarea">
                            Enter or upload the CSR in PEM format below
                        </label>
                        <textarea id="csr-textarea" name="textarea" rows={10} placeholder="-----BEGIN CERTIFICATE REQUEST-----" onChange={handleTextChange} value={CSRPEMString} />
                    </div>
                    <div className="p-form__group row">
                        <input type="file" name="upload" accept=".pem,.csr" onChange={handleFileChange}></input>
                    </div>
                    <div className="p-form__group row">
                        <SubmitCSR csrText={CSRPEMString} errorText={errorText} onClickFunc={() => mutation.mutate({ authToken: cookies.user_token, csr: CSRPEMString })} />
                    </div>
                </form>
            </div>
        </div >
    )
}

function SubmitCSR({ csrText, errorText, onClickFunc }: { csrText: string, errorText: string, onClickFunc: any }) {
    let csrIsValid = false
    try {
        extractCSR(csrText.trim())
        csrIsValid = true
    }
    catch { }
    const validationComponent = csrText == "" ? <></> : csrIsValid ? <div><i className="p-icon--success"></i>Valid CSR</div> : <div><i className="p-icon--error"></i>Invalid CSR</div>
    const buttonComponent = csrIsValid ? (
        <button className="p-button--positive u-float-right" name="submit" onClick={(e) => { e.preventDefault(); onClickFunc() }} > Submit</button >
    ) : (
        <button className="p-button--positive u-float-right" name="submit" disabled={true} onClick={(e) => { e.preventDefault(); onClickFunc() }} >Submit</button>)
    return (
        <>
            {errorText != "" &&
                <div className="p-notification--negative">
                    <div className="p-notification__content">
                        <h5 className="p-notification__title">Error</h5>
                        <p className="p-notification__message">{errorText.split("error: ")}</p>
                    </div>
                </div>
            }
            {validationComponent}
            {buttonComponent}
        </>
    )
}
import { SetStateAction, Dispatch, useState, createContext, ChangeEvent } from "react"
import { useMutation, useQueryClient } from "react-query";
import { postCSR } from "./queries";
import { extractCSR } from "./utils";
import { useCookies } from "react-cookie";

type AsideContextType = {
    isOpen: boolean,
    setIsOpen: Dispatch<SetStateAction<boolean>>
}
export const AsideContext = createContext<AsideContextType>({ isOpen: false, setIsOpen: () => { } });

export function Aside({ isOpen, setIsOpen }: { isOpen: boolean, setIsOpen: Dispatch<SetStateAction<boolean>> }) {
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const queryClient = useQueryClient()
    const mutation = useMutation(postCSR, {
        onSuccess: () => {
            queryClient.invalidateQueries('csrs')
        },
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
        <aside className={"l-aside" + (isOpen ? "" : " is-collapsed")} id="aside-panel" aria-label="aside-panel" >
            <div className="p-panel">
                <div className="p-panel__header">
                    <h4 className="p-panel__title">Add a New Certificate Request</h4>
                    <div className="p-panel__controls">
                        <button onClick={() => setIsOpen(false)} className="p-button--base u-no-margin--bottom has-icon"><i className="p-icon--close"></i></button>
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
                            <SubmitCSR csrText={CSRPEMString} onClickFunc={() => mutation.mutate({ authToken: cookies.user_token, csr: CSRPEMString })} />
                        </div>
                    </form>
                </div>
            </div >
        </aside >
    )
}

function SubmitCSR({ csrText, onClickFunc }: { csrText: string, onClickFunc: any }) {
    let csrIsValid = false
    try {
        extractCSR(csrText.trim())
        csrIsValid = true
    }
    catch { }

    const validationComponent = csrText == "" ? <></> : csrIsValid ? <div><i className="p-icon--success"></i>Valid CSR</div> : <div><i className="p-icon--error"></i>Invalid CSR</div>
    const buttonComponent = csrIsValid ? <button className="p-button--positive u-float-right" name="submit" onClick={onClickFunc} >Submit</button> : <button className="p-button--positive u-float-right" name="submit" disabled={true} onClick={onClickFunc} >Submit</button>
    return (
        <>
            {validationComponent}
            {buttonComponent}
        </>
    )
}
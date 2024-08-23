import { Dispatch, SetStateAction, useState, ChangeEvent, useEffect } from "react"
import { useMutation, useQueryClient } from "react-query"
import { ConfirmationModalData } from "./row"
import { csrMatchesCertificate, splitBundle, validateBundle } from "../utils"
import { postCertToID } from "../queries"
import { useCookies } from "react-cookie"

interface ConfirmationModalProps {
    modalData: ConfirmationModalData
    setModalData: Dispatch<SetStateAction<ConfirmationModalData>>
}


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

function SubmitCertificate({ existingCSRText, existingCertText, certText, onClickFunc }: { existingCSRText: string, existingCertText: string, certText: string, onClickFunc: any }) {
    const [validationErrorText, setValidationErrorText] = useState<string>("")
    useEffect(() => {
        const validateCertificate = async () => {
            try {
                const certs = splitBundle(certText)
                if (certs.length < 2) {
                    setValidationErrorText("bundle with 2 certificates required")
                    return
                }
                if (!csrMatchesCertificate(existingCSRText, certs[0])) {
                    setValidationErrorText("Certificate does not match request")
                    return
                }
                let a = await validateBundle(certText)
                if (await validateBundle(certText)) {
                    setValidationErrorText("Bundle validation failed: " + a)
                    return
                }
            }
            catch {
                setValidationErrorText("A certificate is invalid")
                return
            }
            setValidationErrorText("")
        }
        validateCertificate()
    }, [existingCSRText, existingCertText, certText])

    const validationComponent = certText != "" && validationErrorText == "" ? (
        <div><i className="p-icon--success"></i> Valid Certificate</div>
    ) : (
        <div><i className="p-icon--error"></i> {validationErrorText}</div>)
    const buttonComponent = validationErrorText == "" ? (
        <button className="p-button--positive" name="submit" onClick={onClickFunc} >Submit</button>
    ) : (
        <button className="p-button--positive" name="submit" disabled={true} onClick={onClickFunc} >Submit</button>
    )
    return (
        <>
            {validationComponent}
            {buttonComponent}
        </>
    )
}

interface SubmitCertificateModalProps {
    id: string
    csr: string
    cert: string
    setFormOpen: Dispatch<SetStateAction<boolean>>
}
export function SubmitCertificateModal({ id, csr, cert, setFormOpen }: SubmitCertificateModalProps) {
    const [cookies, setCookie, removeCookie] = useCookies(['user_token']);
    const [errorText, setErrorText] = useState<string>("")
    const queryClient = useQueryClient()
    const mutation = useMutation(postCertToID, {
        onSuccess: () => {
            queryClient.invalidateQueries('csrs')
            setErrorText("")
            setFormOpen(false)
        },
        onError: (e: Error) => {
            setErrorText(e.message)
        }
    })
    const [certificatePEMString, setCertificatePEMString] = useState<string>("")
    const handleTextChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
        setCertificatePEMString(event.target.value);
    }
    const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (file) {
            const reader = new FileReader();
            reader.onload = (e: ProgressEvent<FileReader>) => {
                if (e.target) {
                    if (e.target.result) {
                        setCertificatePEMString(e.target.result.toString());
                    }
                }
            };
            reader.readAsText(file);
        }
    };
    return (
        <div className="p-modal" id="modal">
            <section className="p-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-description">
                <header className="p-modal__header">
                    <h2 className="p-modal__title" id="modal-title">Submit Certificate</h2>
                </header>
                <form className="p-form p-form--stacked">
                    <div className="p-form__group row">
                        <label htmlFor="textarea">
                            Enter or upload the Certificate in PEM format below
                        </label>
                        <textarea id="csr-textarea" name="textarea" rows={10} placeholder="-----BEGIN CERTIFICATE-----" onChange={handleTextChange} value={certificatePEMString} />
                    </div>
                    <div className="p-form__group row">
                        <input type="file" name="upload" accept=".pem,.crt" onChange={handleFileChange}></input>
                    </div>
                    <div className="p-form__group row">
                    </div>
                </form>
                <footer className="p-modal__footer">
                    {errorText != "" &&
                        <div className="p-notification--negative">
                            <div className="p-notification__content">
                                <h5 className="p-notification__title">Error</h5>
                                <p className="p-notification__message">{errorText.split("error: ")}</p>
                            </div>
                        </div>
                    }
                    <SubmitCertificate existingCSRText={csr.trim()} existingCertText={cert.trim()} certText={certificatePEMString.trim()} onClickFunc={() => mutation.mutate({ id: id, authToken: cookies.user_token, cert: splitBundle(certificatePEMString).join("\n") })} />
                    <button className="u-no-margin--bottom" aria-controls="modal" onMouseDown={() => setFormOpen(false)}>Cancel</button>
                </footer>
            </section>
        </div>
    )
}

export function SuccessNotification({ successMessage }: { successMessage: string }) {
    const style = {
        display: 'inline'
    }
    return (
        <p style={style}>
            <i className="p-icon--success"></i> {successMessage}
        </p>
    );
}
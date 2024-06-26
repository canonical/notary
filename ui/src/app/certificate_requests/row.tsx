import { useState, Dispatch, SetStateAction, useEffect, useRef } from "react"
import { UseMutationResult, useMutation, useQueryClient } from "react-query"
import { extractCSR, extractCert } from "../utils"
import { deleteCSR, rejectCSR } from "../queries"
import { ConfirmationModal, SuccessNotification } from "./components"

type rowProps = {
    id: number,
    csr: string,
    certificate: string

    ActionMenuExpanded: number
    setActionMenuExpanded: Dispatch<SetStateAction<number>>
}
export type ConfirmationModalData = {
    func: () => void
    warningText: string
} | null

export default function Row({ id, csr, certificate, ActionMenuExpanded, setActionMenuExpanded }: rowProps) {
    const [successNotification, setSuccessNotification] = useState<string | null>(null)
    const [detailsMenuOpen, setDetailsMenuOpen] = useState<boolean>(false)
    const [confirmationModalData, setConfirmationModalData] = useState<ConfirmationModalData>(null)

    const csrObj = extractCSR(csr)
    const certObj = extractCert(certificate)

    const queryClient = useQueryClient()
    const deleteMutation = useMutation(deleteCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    })
    const rejectMutation = useMutation(rejectCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    })

    const mutationFunc = (mutation: UseMutationResult<any, unknown, string, unknown>) => {
        mutation.mutate(id.toString())
    }
    const handleReject = () => {
        setConfirmationModalData({
            func: () => mutationFunc(rejectMutation),
            warningText: "Rejecting a Certificate Request means the CSR will remain in this application, but its status will be moved to rejected and the associated certificate will be deleted if there is any. This action cannot be undone."
        })
    }
    const handleDelete = () => {
        setConfirmationModalData({
            func: () => mutationFunc(deleteMutation),
            warningText: "Deleting a Certificate Request means this row will be completely removed from the application. This action cannot be undone."
        })
    }
    const handleCopy = () => {
        navigator.clipboard.writeText(csr).then(function () {
            setSuccessNotification("CSR copied to clipboard")
            setTimeout(() => {
                setSuccessNotification(null);
            }, 2500);
        }, function (err) {
            console.error('could not copy text: ', err);
        });
    }
    const handleDownload = () => {
        const blob = new Blob([csr], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = "csr.pem"; // TODO: change this to <csr-commonname>.pem
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(link.href);
    };

    const toggleActionMenu = () => {
        if (ActionMenuExpanded == id) {
            setActionMenuExpanded(0)
        } else {
            setActionMenuExpanded(id)
        }
    }
    return (
        <>
            <tr>
                <td className="" width={5} aria-label="id">{id}</td>
                <td className="">
                    <button
                        className="u-toggle p-contextual-menu__toggle p-button--base is-small"
                        aria-controls="expanded-row"
                        aria-expanded={detailsMenuOpen ? "true" : "false"}
                        onClick={() => setDetailsMenuOpen(!detailsMenuOpen)}>
                        <i className="p-icon--chevron-down p-contextual-menu__indicator"></i>
                    </button>
                    <span>{csrObj.subjects.find((e) => e.type == "Common Name")?.value}</span>
                </td>
                <td className="" aria-label="csr-status">{certificate == "" ? "outstanding" : (certificate == "rejected" ? "rejected" : "fulfilled")}</td>
                <td className="" aria-label="certificate-expiry-date">{certificate == "" ? "" : (certificate == "rejected" ? "" : certObj?.notAfter)}</td>
                <td className="has-overflow" data-heading="Actions">
                    <span className="p-contextual-menu--center u-no-margin--bottom">
                        <button
                            className="p-contextual-menu__toggle p-button--base is-small u-no-margin--bottom"
                            aria-label="action-menu-button"
                            aria-controls="action-menu"
                            aria-expanded={ActionMenuExpanded == id ? "true" : "false"}
                            aria-haspopup="true"
                            onClick={toggleActionMenu}
                            onBlur={toggleActionMenu}>
                            <i className="p-icon--menu p-contextual-menu__indicator"></i>
                        </button>
                        {successNotification && <SuccessNotification successMessage={successNotification} />}
                        <span className="p-contextual-menu__dropdown" id="action-menu" aria-hidden={ActionMenuExpanded == id ? "false" : "true"}>
                            <span className="p-contextual-menu__group">
                                <button className="p-contextual-menu__link" onMouseDown={handleCopy}>Copy Certificate Request to Clipboard</button>
                                <button className="p-contextual-menu__link" onMouseDown={handleDownload}>Download Certificate Request</button>
                                {certificate == "rejected" ?
                                    <button className="p-contextual-menu__link" disabled={true} onMouseDown={handleReject}>Reject Certificate Request</button> :
                                    <button className="p-contextual-menu__link" onMouseDown={handleReject}>Reject Certificate Request</button>}
                                <button className="p-contextual-menu__link" onMouseDown={handleDelete}>Delete Certificate Request</button>
                            </span>
                            <span className="p-contextual-menu__group">
                                <button className="p-contextual-menu__link">Upload Certificate</button>
                                <button className="p-contextual-menu__link">Revoke Certificate</button>
                            </span>
                        </span>
                    </span>
                </td>
                <td id="expanded-row" className="p-table__expanding-panel" aria-hidden={detailsMenuOpen ? "false" : "true"}>
                    <div className="row">
                        <div className="col-8">
                            <p><b>Common Name</b>: {csrObj.subjects.find((e) => e.type == "Common Name")?.value}</p>
                        </div>
                    </div>
                </td>
            </tr>
            {confirmationModalData != null && <ConfirmationModal modalData={confirmationModalData} setModalData={setConfirmationModalData} />}
        </>
    )
}
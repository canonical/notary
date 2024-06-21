import { useState, Dispatch, SetStateAction, useEffect, useRef } from "react"
import { useMutation, useQueryClient } from "react-query"
import { extractCSR, extractCert } from "../utils"
import { deleteCSR, rejectCSR } from "../queries"


type rowProps = {
    id: number,
    csr: string,
    certificate: string

    ActionMenuExpanded: number
    setActionMenuExpanded: Dispatch<SetStateAction<number>>
}
export default function Row({ id, csr, certificate, ActionMenuExpanded, setActionMenuExpanded }: rowProps) {
    const [detailsMenuOpen, setDetailsMenuOpen] = useState<boolean>(false)

    const csrObj = extractCSR(csr)
    const certObj = extractCert(certificate)

    const queryClient = useQueryClient()
    const deleteMutation = useMutation(deleteCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    })
    const rejectMutation = useMutation(rejectCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    })

    const toggleActionMenu = () => {
        if (ActionMenuExpanded == id) {
            setActionMenuExpanded(0)
        } else {
            setActionMenuExpanded(id)
        }
    }
    return (
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
                    <span className="p-contextual-menu__dropdown" id="action-menu" aria-hidden={ActionMenuExpanded == id ? "false" : "true"}>
                        <span className="p-contextual-menu__group">
                            <button className="p-contextual-menu__link">Copy Certificate Request to Clipboard</button>
                            <button className="p-contextual-menu__link">Download Certificate Request</button>
                            <button className="p-contextual-menu__link" onMouseDown={() => rejectMutation.mutate(id.toString())}>Reject Certificate Request</button>
                            <button className="p-contextual-menu__link" onMouseDown={() => deleteMutation.mutate(id.toString())}>Delete Certificate Request</button>
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
    )
}
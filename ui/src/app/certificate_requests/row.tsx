import { useState, Dispatch, SetStateAction } from "react"
const extractCSR = (csrPemString: string) => {
    //TODO
}

const extractCert = (certPemString: string) => {
    //TODO
}

type rowProps = {
    id: number,
    csr: string,
    certificate: string

    ActionMenuExpanded: number
    setActionMenuExpanded: Dispatch<SetStateAction<number>>
}
export default function Row({ id, csr, certificate, ActionMenuExpanded, setActionMenuExpanded }: rowProps) {
    const [detailsMenuOpen, setDetailsMenuOpen] = useState<boolean>(false)

    const toggleActionMenu = () => {
        if (ActionMenuExpanded == id) {
            setActionMenuExpanded(0)
        }else{
            setActionMenuExpanded(id)
        }
    }
    return (
        <tr>
            <td className="" width={5} data-test-column="id">{id}</td>
            <td className="">
                <button 
                    className="u-toggle p-contextual-menu__toggle p-button--base is-small" 
                    aria-controls="expanded-row"
                    aria-expanded={detailsMenuOpen? "true": "false"}
                    onClick={() => setDetailsMenuOpen(!detailsMenuOpen)}>
                        <i className="p-icon--chevron-down p-contextual-menu__indicator"></i>
                </button>
                <span> example.com</span>
            </td>
            <td className="" data-test-column="status">{certificate == "" ? "outstanding" : (certificate == "rejected" ? "rejected" : "fulfilled")}</td>
            <td className="" data-test-column="status">{certificate == "" ? "" : (certificate == "rejected" ? "" : "date")}</td>
            <td className="has-overflow" data-heading="Actions">
                <span className="p-contextual-menu--center u-no-margin--bottom">
                    <button 
                        className="p-contextual-menu__toggle p-button--base is-small u-no-margin--bottom" 
                        aria-controls="action-menu" 
                        aria-expanded={ActionMenuExpanded == id ? "true": "false"} 
                        aria-haspopup="true" 
                        onClick={toggleActionMenu}
                        onBlur={toggleActionMenu}>
                            <i className="p-icon--menu p-contextual-menu__indicator"></i>
                    </button>
                    <span className="p-contextual-menu__dropdown" id="action-menu" aria-hidden={ActionMenuExpanded == id? "false": "true"}>
                        <span className="p-contextual-menu__group">
                            <button className="p-contextual-menu__link">Copy Certificate Request to Clipboard</button>
                            <button className="p-contextual-menu__link">Download Certificate Request</button>
                            <button className="p-contextual-menu__link">Reject Certificate Request</button>
                            <button className="p-contextual-menu__link">Delete Certificate Request</button>
                        </span>
                        <span className="p-contextual-menu__group">
                            <button className="p-contextual-menu__link">Upload Certificate</button>
                            <button className="p-contextual-menu__link">Revoke Certificate</button>
                        </span>
                    </span>
                </span>
            </td>
            <td id="expanded-row" className="p-table__expanding-panel" aria-hidden={detailsMenuOpen? "false": "true"}>
                <div className="row">
                    <div className="col-8">
                        <p><b>Common Name</b>: example.com</p>
                        <p><b>Subject Alternative Names</b>: example.com, 127.0.0.1, 1.2.3.4.5.56</p>
                    </div>
                </div>
            </td>
        </tr>
    )
}
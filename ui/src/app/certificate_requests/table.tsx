import { Dispatch, SetStateAction, useContext } from "react"
import { AsideContext } from "../nav"
import Row from "./row"


export function CertificateRequestsTable() {
    const { isOpen: isAsideOpen, setIsOpen: setAsideIsOpen } = useContext(AsideContext)
    return (
        <div className="p-panel">
            <div className="p-panel__header is-sticky">
                <h4 className="p-panel__title">Certificate Requests</h4>
                <div className="p-panel__controls">
                    <button className="u-no-margin--bottom p-button--positive" aria-label="add-csr-button" onClick={() => setAsideIsOpen(true)}>Add New CSR</button>
                </div>
            </div>
            <div className="p-panel__content">
                <div className="u-fixed-width">
                    <table aria-label="Certificate Requests Table" className="p-main-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Details</th>
                                <th>Status</th>
                                <th>Sign/Reject</th>
                                <th>Delete</th>
                            </tr>
                        </thead>
                        <tbody>
                            <Row id={1} csr="csr1" certificate="" />
                            <Row id={2} csr="csr2" certificate="rejected" />
                            <Row id={3} csr="csr3" certificate="a real cert" />
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
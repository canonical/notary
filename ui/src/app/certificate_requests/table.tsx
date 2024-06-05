import { useContext, useState } from "react"
import { AsideContext } from "../nav"
import Row from "./row"

type CSREntry = {
    id: number,
    csr: string,
    certificate: string
}

function sortByCSRStatus(a: CSREntry, b: CSREntry) {
    const aCSRStatus = a.certificate == "" ? "outstanding" : (a.certificate == "rejected" ? "rejected" : "fulfilled")
    const bCSRStatus = b.certificate == "" ? "outstanding" : (b.certificate == "rejected" ? "rejected" : "fulfilled")
    if (aCSRStatus < bCSRStatus) {
        return -1;
    } else if (aCSRStatus > bCSRStatus) {
        return 1;
    } else {
        return 0;
    }
}

function sortByCertStatus(a: CSREntry, b: CSREntry) {
    const aCertStatus = (a.certificate == "" ? "" : (a.certificate == "rejected" ? "" : "date"))
    const bCertStatus = (b.certificate == "" ? "" : (b.certificate == "rejected" ? "" : "date"))
    if (aCertStatus < bCertStatus) {
        return -1;
    } else if (aCertStatus > bCertStatus) {
        return 1;
    } else {
        return 0;
    }
}

export function CertificateRequestsTable() {
    const { isOpen: isAsideOpen, setIsOpen: setAsideIsOpen } = useContext(AsideContext)
    const [sortedColumn, setSortedColumn] = useState<string>('none')
    const [sortDescending, setSortDescending] = useState<boolean>(true)
    const rows = [
        {'id':1, 'csr':"csr1",'certificate':""},
        {'id':2, 'csr':"csr2",'certificate':"rejected"},
        {'id':3, 'csr':"csr3",'certificate':"a real cert"},
        {'id':4, 'csr':"csr3",'certificate':"a real cert"},
        {'id':5, 'csr':"csr3",'certificate':"a real cert"},
        {'id':6, 'csr':"csr3",'certificate':"a real cert"},
    ]
    const sortedRows = () => {
        switch (sortedColumn) {
            case "csr":
                return (sortDescending? rows.sort(sortByCSRStatus).reverse() : rows.sort(sortByCSRStatus))
            case "cert":
                return (sortDescending? rows.sort(sortByCertStatus).reverse() : rows.sort(sortByCertStatus))
            default:
                return rows
        }
    }
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
                    <table id="csr-table" aria-label="Certificate Requests Table" className="p-table--expanding">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Details</th>
                                <th aria-sort={sortedColumn == "csr"? (sortDescending? "descending": "ascending"): "none"} onClick={() => {setSortedColumn('csr');setSortDescending(!sortDescending)}}>CSR Status</th>
                                <th aria-sort={sortedColumn == "cert"? (sortDescending? "descending": "ascending"): "none"} onClick={() => {setSortedColumn('cert');setSortDescending(!sortDescending)}}>Certificate Expiry Date</th>
                                <th className="has-overflow">Actions</th>
                                <th aria-hidden="true"></th>
                            </tr>
                        </thead>
                        <tbody>
                            {
                                sortedRows().map((row) => (
                                    <Row key={row.id} id={row.id} csr={row.csr} certificate={row.certificate}/> 
                                )
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    )
}
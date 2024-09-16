import { useContext, useState, Dispatch, SetStateAction } from "react";
import { AsideContext } from "../aside";
import { CSREntry } from "../types";
import { Button, MainTable } from "@canonical/react-components";
import Row from "./row";

function EmptyState({ asideOpen, setAsideOpen }: { asideOpen: boolean; setAsideOpen: Dispatch<SetStateAction<boolean>> }) {
    return (
        <div className="p-strip">
            <div className="row">
                <div className="col-8 col-medium-4 col-small-3">
                    <p className="p-heading--4">No CSRs available yet.</p>
                    <Button appearance="positive" onClick={() => setAsideOpen(true)}>
                        Add New CSR
                    </Button>
                </div>
            </div>
        </div>
    );
}

type TableProps = {
    csrs: CSREntry[];
};

function sortByCSRStatus(a: CSREntry, b: CSREntry) {
    const aCSRStatus = a.certificate === "" ? "outstanding" : a.certificate === "rejected" ? "rejected" : "fulfilled";
    const bCSRStatus = b.certificate === "" ? "outstanding" : b.certificate === "rejected" ? "rejected" : "fulfilled";
    return aCSRStatus.localeCompare(bCSRStatus);
}

function sortByCertStatus(a: CSREntry, b: CSREntry) {
    const aCertStatus = a.certificate === "" || a.certificate === "rejected" ? "" : "date";
    const bCertStatus = b.certificate === "" || b.certificate === "rejected" ? "" : "date";
    return aCertStatus.localeCompare(bCertStatus);
}

export function CertificateRequestsTable({ csrs }: TableProps) {
    const { isOpen: isAsideOpen, setIsOpen: setAsideIsOpen } = useContext(AsideContext);

    const [actionsMenuExpanded, setActionsMenuExpanded] = useState<number>(0);
    const [sortedColumn, setSortedColumn] = useState<string>("none");
    const [sortDescending, setSortDescending] = useState<boolean>(true);

    const sortedRows = () => {
        switch (sortedColumn) {
            case "csr":
                return sortDescending ? csrs.sort(sortByCSRStatus).reverse() : csrs.sort(sortByCSRStatus);
            case "cert":
                return sortDescending ? csrs.sort(sortByCertStatus).reverse() : csrs.sort(sortByCertStatus);
            default:
                return csrs;
        }
    };

    return (
        <div className="p-panel">
            <div className="p-panel__header is-sticky">
                <h4 className="p-panel__title">Certificate Requests</h4>
                <div className="p-panel__controls">
                    {csrs.length > 0 && (
                        <Button appearance="positive" onClick={() => setAsideIsOpen(true)}>
                            Add New CSR
                        </Button>
                    )}
                </div>
            </div>
            <div className="p-panel__content">
                <div className="u-fixed-width">
                    <MainTable
                        expanding
                        headers={[
                            { content: "ID" },
                            { content: "Common Name" },
                            { content: "CSR Status" },
                            { content: "Certificate Expiry Date" },
                            { content: "Actions", className: "u-align--right has-overflow" }
                        ]}
                        rows={sortedRows().map((csr) =>
                            Row({
                                id: csr.id,
                                csr: csr.csr,
                                certificate: csr.certificate,
                            })
                        )}
                    />
                    {csrs.length === 0 && <EmptyState asideOpen={isAsideOpen} setAsideOpen={setAsideIsOpen} />}
                </div>
            </div>
        </div>
    );
}

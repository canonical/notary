import { useContext, useState, Dispatch, SetStateAction } from "react";
import { AsideContext } from "../aside";
import { CSREntry } from "../types";
import { Button, MainTable, Panel, EmptyState } from "@canonical/react-components";
import Row from "./row";

function CSREmptyState({ setAsideOpen }: { setAsideOpen: Dispatch<SetStateAction<boolean>> }) {
    return (
        <EmptyState
            image={""}
            title="No CSRs available yet."
        >
            <p>
                There are no Certificate Requests in Notary. Request your first certificate!
            </p>
            <Button
                appearance="positive"
                aria-label="add-csr-button"
                onClick={() => setAsideOpen(true)}>
                Add New CSR
            </Button>
        </EmptyState>
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
        <Panel
            stickyHeader
            title="Certificate Requests"
            className="u-fixed-width"
            controls={csrs.length > 0 && (
                <Button appearance="positive" onClick={() => setAsideIsOpen(true)}>
                    Add New CSR
                </Button>
            )}
        >
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
            {csrs.length === 0 && <CSREmptyState setAsideOpen={setAsideIsOpen} />}
        </Panel>
    );
}

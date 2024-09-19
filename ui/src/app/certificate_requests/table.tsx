import { useContext, useState, Dispatch, SetStateAction } from "react";
import { AsideContext } from "../aside";
import { CSREntry } from "../types";
import { Button, MainTable, Panel, EmptyState, ContextualMenu, ConfirmationModal } from "@canonical/react-components";
import { RequiredCSRParams, deleteCSR, rejectCSR, revokeCertificate } from "../queries"
import { useCookies } from "react-cookie";
import { extractCSR, extractCert, splitBundle } from "../utils";
import { UseMutationResult, useMutation, useQueryClient } from "react-query"
import { SubmitCertificateModal, SuccessNotification } from "./components"


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

export type ConfirmationModalData = {
    onMouseDownFunc: () => void
    warningText: string
} | null


export function CertificateRequestsTable({ csrs: rows }: TableProps) {
    const { isOpen: isAsideOpen, setIsOpen: setAsideIsOpen } = useContext(AsideContext);
    const [cookies] = useCookies(['user_token']);
    const queryClient = useQueryClient();
    const [certificateFormOpen, setCertificateFormOpen] = useState<boolean>(false);
    const [confirmationModalData, setConfirmationModalData] = useState<ConfirmationModalData | null>(null);
    const [selectedCSR, setSelectedCSR] = useState<CSREntry | null>(null);
    const [showCSRContent, setShowCSRContent] = useState<number | null>(null);
    const [showCertContent, setShowCertContent] = useState<number | null>(null);
    const [successNotificationId, setSuccessNotificationId] = useState<number | null>(null);

    const deleteMutation = useMutation(deleteCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs'),
    });

    const rejectMutation = useMutation(rejectCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs'),
    });

    const revokeMutation = useMutation(revokeCertificate, {
        onSuccess: () => queryClient.invalidateQueries('csrs'),
    });

    const mutationFunc = (mutation: UseMutationResult<any, unknown, RequiredCSRParams, unknown>, params: RequiredCSRParams) => {
        mutation.mutate(params);
        setConfirmationModalData(null);
    };

    const handleCopy = (csr: string, id: number) => {
        navigator.clipboard.writeText(csr).then(() => {
            setSuccessNotificationId(id);
            setTimeout(() => setSuccessNotificationId(null), 2500);
        });
    };

    const handleDownload = (csr: string, id: number, csrObj: any) => {
        const blob = new Blob([csr], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `csr-${csrObj.commonName || id}.pem`;
        link.click();
        URL.revokeObjectURL(link.href);
    };

    const handleReject = (id: number) => {
        setConfirmationModalData({
            onMouseDownFunc: () => mutationFunc(rejectMutation, { id: id.toString(), authToken: cookies.user_token }),
            warningText: "Rejecting a Certificate Request means the CSR will remain in this application, but its status will be moved to rejected and the associated certificate will be deleted if there is any. This action cannot be undone.",
        });
    };

    const handleDelete = (id: number) => {
        setConfirmationModalData({
            onMouseDownFunc: () => mutationFunc(deleteMutation, { id: id.toString(), authToken: cookies.user_token }),
            warningText: "Deleting a Certificate Request means this row will be completely removed from the application. This action cannot be undone.",
        });
    };

    const handleRevoke = (id: number) => {
        setConfirmationModalData({
            onMouseDownFunc: () => mutationFunc(revokeMutation, { id: id.toString(), authToken: cookies.user_token }),
            warningText: "Revoking a Certificate will delete it from the table. This action cannot be undone.",
        });
    };

    const handleExpand = (id: number, type: 'CSR' | 'Cert') => {
        if (type === 'CSR') {
            setShowCSRContent(id === showCSRContent ? null : id);
            setShowCertContent(null);
        } else {
            setShowCertContent(id === showCertContent ? null : id);
            setShowCSRContent(null);
        }
    };

    const getExpiryColor = (notAfter?: string): string => {
        if (!notAfter) return 'inherit';
        const expiryDate = new Date(notAfter);
        const now = new Date();
        const timeDifference = expiryDate.getTime() - now.getTime();
        if (timeDifference < 0) return "rgba(199, 22, 43, 1)";
        if (timeDifference < 24 * 60 * 60 * 1000) return "rgba(249, 155, 17, 0.45)";
        return "rgba(14, 132, 32, 0.35)";
    };

    const getFieldDisplay = (label: string, field: string | undefined, compareField?: string | undefined) => {
        const isMismatched = compareField !== undefined && compareField !== field;
        return field ? (
            <p style={{ marginBottom: "4px" }}>
                <b>{label}:</b>{" "}
                <span style={{ color: isMismatched ? "rgba(199, 22, 43, 1)" : "inherit" }}>
                    {field}
                </span>
            </p>
        ) : null;
    };

    const csrrows = rows.map((csrEntry) => {
        const { id, csr, certificate } = csrEntry;
        const csrObj = extractCSR(csr);
        const certs = splitBundle(certificate);
        const clientCertificate = certs?.at(0);
        const certObj = clientCertificate ? extractCert(clientCertificate) : null;

        const isCSRContentVisible = showCSRContent === id;
        const isCertContentVisible = showCertContent === id;

        return {
            sortData: {
                id,
                common_name: csrObj.commonName,
                csr_status: certificate === "" ? "outstanding" : (certificate === "rejected" ? "rejected" : "fulfilled"),
                cert_expiry_date: certObj?.notAfter || "",
            },
            columns: [
                { content: id.toString() },
                { content: csrObj.commonName || "N/A" },
                { content: certificate === "" ? "outstanding" : (certificate === "rejected" ? "rejected" : "fulfilled") },
                {
                    content: certObj?.notAfter || "",
                    style: { backgroundColor: getExpiryColor(certObj?.notAfter) },
                },
                {
                    content: (
                        <>
                            {successNotificationId === id && <SuccessNotification successMessage="CSR copied to clipboard" />}
                            <ContextualMenu
                                links={[
                                    {
                                        children: "Copy Certificate Request to Clipboard",
                                        onClick: () => handleCopy(csr, id)
                                    },
                                    {
                                        children: "Download Certificate Request",
                                        onClick: () => handleDownload(csr, id, csrObj)
                                    },
                                    {
                                        children: isCSRContentVisible ? "Hide CSR content" : "Show CSR content",
                                        onClick: () => handleExpand(id, 'CSR'),
                                    },
                                    {
                                        children: isCertContentVisible ? "Hide Certificate content" : "Show Certificate content",
                                        onClick: () => handleExpand(id, 'Cert'),
                                        disabled: !certObj,
                                    },
                                    {
                                        children: "Reject Certificate Request",
                                        disabled: certificate === "rejected",
                                        onClick: () => handleReject(id),
                                    },
                                    {
                                        children: "Delete Certificate Request",
                                        onClick: () => handleDelete(id),
                                    },
                                    {
                                        children: "Upload Certificate",
                                        onClick: () => {
                                            setCertificateFormOpen(true);
                                            setSelectedCSR(csrEntry);
                                        },
                                    },
                                    {
                                        children: "Revoke Certificate",
                                        disabled: certificate === "rejected" || certificate === "",
                                        onClick: () => handleRevoke(id),
                                    },
                                ]}
                                hasToggleIcon
                                position="right"
                            />
                        </>
                    ),
                    className: "u-align--right has-overflow",
                    style: { height: "58px", overflow: "hidden" },
                },
            ],
            expanded: isCSRContentVisible || isCertContentVisible,
            expandedContent: (
                <div >
                    {isCSRContentVisible && (
                        <div >
                            <h4>Certificate Request Content</h4>
                            {getFieldDisplay("Common Name", csrObj.commonName)}
                            {getFieldDisplay("Subject Alternative Name DNS", csrObj.sansDns?.join(', '))}
                            {getFieldDisplay("Subject Alternative Name IP addresses", csrObj.sansIp?.join(', '))}
                            {getFieldDisplay("Country", csrObj.country)}
                            {getFieldDisplay("State or Province", csrObj.stateOrProvince)}
                            {getFieldDisplay("Locality", csrObj.locality)}
                            {getFieldDisplay("Organization", csrObj.organization)}
                            {getFieldDisplay("Organizational Unit", csrObj.OrganizationalUnitName)}
                            {getFieldDisplay("Email Address", csrObj.emailAddress)}
                            <p><b>Certificate request for a certificate authority</b>: {csrObj.is_ca ? "Yes" : "No"}</p>
                        </div>
                    )}
                    {isCertContentVisible && certObj && (
                        <div >
                            <h4>Certificate Content</h4>
                            {getFieldDisplay("Common Name", certObj.commonName)}
                            {getFieldDisplay("Subject Alternative Name DNS", certObj.sansDns?.join(', '))}
                            {getFieldDisplay("Subject Alternative Name IP addresses", certObj.sansIp?.join(', '))}
                            {getFieldDisplay("Country", certObj.country)}
                            {getFieldDisplay("State or Province", certObj.stateOrProvince)}
                            {getFieldDisplay("Locality", certObj.locality)}
                            {getFieldDisplay("Organization", certObj.organization)}
                            {getFieldDisplay("Organizational Unit", certObj.OrganizationalUnitName)}
                            {getFieldDisplay("Email Address", certObj.emailAddress)}
                            {getFieldDisplay("Start of validity", certObj.notBefore)}
                            {getFieldDisplay("Expiry Time", certObj.notAfter)}
                            {getFieldDisplay("Issuer Common Name", certObj.issuerCommonName)}
                            <p><b>Certificate for a certificate authority</b>: {certObj.is_ca ? "Yes" : "No"}</p>
                        </div>
                    )}
                </div>
            ),
        };
    });
    return (
        <Panel
            stickyHeader
            title="Certificate Requests"
            className="u-fixed-width"
            controls={rows.length > 0 && (
                <Button appearance="positive" onClick={() => setAsideIsOpen(true)}>
                    Add New CSR
                </Button>
            )}
        >
            <MainTable
                emptyStateMsg={<CSREmptyState setAsideOpen={setAsideIsOpen} />}
                expanding
                sortable
                headers={[
                    {
                        content: "ID",
                        sortKey: "id",
                    },
                    {
                        content: "Common Name",
                        sortKey: "common_name",
                    },
                    {
                        content: "CSR Status",
                        sortKey: "csr_status",
                    },
                    {
                        content: "Certificate Expiry Date",
                        sortKey: "cert_expiry_date",
                    },
                    {
                        content: "Actions",
                        className: "u-align--right has-overflow"
                    }
                ]}
                rows={csrrows}
            />
            {confirmationModalData && (
                <ConfirmationModal
                    title="Confirm Action"
                    confirmButtonLabel="Confirm"
                    onConfirm={confirmationModalData.onMouseDownFunc}
                    close={() => setConfirmationModalData(null)}
                >
                    <p>{confirmationModalData.warningText}</p>
                </ConfirmationModal>
            )}
            {certificateFormOpen && selectedCSR && (
                <SubmitCertificateModal
                    id={selectedCSR.id.toString()}
                    csr={selectedCSR.csr}
                    cert={selectedCSR.certificate}
                    setFormOpen={setCertificateFormOpen}
                />
            )}
        </Panel>
    );
}

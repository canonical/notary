import { useState } from "react";
import { useMutation, useQueryClient } from "react-query";
import { extractCSR, extractCert, splitBundle } from "../utils";
import { deleteCSR, rejectCSR, revokeCertificate } from "../queries";
import { useCookies } from "react-cookie";
import { ContextualMenu } from "@canonical/react-components";
import { SubmitCertificateModal, SuccessNotification } from "./components";

type rowProps = {
    id: number;
    csr: string;
    certificate: string;
};

export default function Row({ id, csr, certificate }: rowProps) {
    const [cookies] = useCookies(['user_token']);
    const [certificateFormOpen, setCertificateFormOpen] = useState<boolean>(false); // State for modal visibility
    const [successNotification, setSuccessNotification] = useState<string | null>(null);
    const [showCSRContent, setShowCSRContent] = useState<boolean>(false);
    const [showCertContent, setShowCertContent] = useState<boolean>(false);

    const csrObj = extractCSR(csr);
    const certs = splitBundle(certificate);
    const clientCertificate = certs?.at(0);
    const certObj = clientCertificate ? extractCert(clientCertificate) : null;

    const queryClient = useQueryClient();

    const deleteMutation = useMutation(deleteCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    });

    const rejectMutation = useMutation(rejectCSR, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    });

    const revokeMutation = useMutation(revokeCertificate, {
        onSuccess: () => queryClient.invalidateQueries('csrs')
    });

    const handleCopy = () => {
        navigator.clipboard.writeText(csr).then(() => {
            setSuccessNotification("CSR copied to clipboard");
            setTimeout(() => setSuccessNotification(null), 2500);
        });
    };

    const handleDownload = () => {
        const blob = new Blob([csr], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `csr-${csrObj.commonName || id}.pem`;
        link.click();
        URL.revokeObjectURL(link.href);
    };

    const handleReject = () => rejectMutation.mutate({ id: id.toString(), authToken: cookies.user_token });
    const handleDelete = () => deleteMutation.mutate({ id: id.toString(), authToken: cookies.user_token });
    const handleRevoke = () => revokeMutation.mutate({ id: id.toString(), authToken: cookies.user_token });

    const getExpiryColor = (notAfter?: string): string => {
        if (!notAfter) return 'inherit';
        const expiryDate = new Date(notAfter);
        const now = new Date();
        const oneDayInMillis = 24 * 60 * 60 * 1000;
        const timeDifference = expiryDate.getTime() - now.getTime();

        if (timeDifference < 0) return "rgba(199, 22, 43, 1)";
        if (timeDifference < oneDayInMillis) return "rgba(249, 155, 17, 0.45)";
        return "rgba(14, 132, 32, 0.35)";
    };

    const getFieldDisplay = (label: string, field: string | undefined, compareField?: string | undefined) => {
        const isMismatched = compareField !== undefined && compareField !== field;
        return field ? (
            <p>
                <b>{label}:</b>{" "}
                <span style={{ color: isMismatched ? "rgba(199, 22, 43, 1)" : 'inherit' }}>
                    {field}
                </span>
            </p>
        ) : null;
    };

    const handleCSRContentToggle = () => {
        setShowCSRContent(!showCSRContent);
        if (!showCSRContent) {
            setShowCertContent(false);
        }
    };

    const handleCertContentToggle = () => {
        setShowCertContent(!showCertContent);
        if (!showCertContent) {
            setShowCSRContent(false);
        }
    };

    return {
        columns: [
            { content: id.toString() },
            { content: csrObj.commonName || "N/A" },
            { content: certificate === "" ? "outstanding" : (certificate === "rejected" ? "rejected" : "fulfilled") },
            {
                content: certificate === "" || certificate === "rejected" ? "" : certObj?.notAfter,
                style: { backgroundColor: getExpiryColor(certObj?.notAfter) }
            },
            {
                content: (
                    <>
                        <ContextualMenu
                            links={[
                                { children: "Copy Certificate Request to Clipboard", onClick: handleCopy },
                                { children: "Download Certificate Request", onClick: handleDownload },
                                {
                                    children: showCSRContent ? "Hide CSR content" : "Show CSR content",
                                    onClick: handleCSRContentToggle
                                },
                                {
                                    children: showCertContent ? "Hide Certificate content" : "Show Certificate content",
                                    onClick: handleCertContentToggle,
                                    disabled: !certObj
                                },
                                {
                                    children: "Reject Certificate Request",
                                    disabled: certificate === "rejected",
                                    onClick: handleReject
                                },
                                { children: "Delete Certificate Request", onClick: handleDelete },
                                { children: "Upload Certificate", onClick: () => setCertificateFormOpen(true) }, // Opens modal
                                {
                                    children: "Revoke Certificate",
                                    disabled: certificate === "rejected" || certificate === "",
                                    onClick: handleRevoke
                                }
                            ]}
                            hasToggleIcon
                            position="right"
                        />

                        {certificateFormOpen && (
                            <SubmitCertificateModal
                                id={id.toString()}
                                csr={csr}
                                cert={certificate}
                                setFormOpen={setCertificateFormOpen}
                            />
                        )}
                    </>
                ),
                className: "u-align--right has-overflow"
            }
        ],
        expanded: showCSRContent || showCertContent,
        expandedContent: (
            <div>
                {showCSRContent && (
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
                {showCertContent && certObj && (
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
        )
    };
}

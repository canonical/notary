import { useState, Dispatch, SetStateAction, useReducer, useRef } from "react";
import { CertificateAuthorityEntry } from "@/types";
import { Button, MainTable, Panel, EmptyState, ContextualMenu } from "@canonical/react-components";
import { deleteCA, makeCALegacy, revokeCA, signCA } from "@/queries"
import { extractCSR, extractCert, splitBundle } from "@/utils";
import { useQueryClient } from "@tanstack/react-query"
import { SubmitCertificateModal, SuccessNotification } from "./components"
import { useAuth } from "@/hooks/useAuth";
import { NotaryConfirmationModalData, NotaryConfirmationModal } from "@/components/NotaryConfirmationModal";


type TableProps = {
  cas: CertificateAuthorityEntry[];
  setAsideOpen: Dispatch<SetStateAction<boolean>>
};

export function CertificateAuthoritiesTable({ cas: rows, setAsideOpen }: TableProps) {
  const auth = useAuth();
  const queryClient = useQueryClient();
  const [certificateFormOpen, setCertificateFormOpen] = useState<boolean>(false);
  const [confirmationModalData, setConfirmationModalData] = useState<NotaryConfirmationModalData | null>(null);
  const [selectedCA, setSelectedCA] = useState<CertificateAuthorityEntry | null>(null);
  const [showCACSRContent, setShowCACSRContent] = useState<number | null>(null);
  const [showCACertificateContent, setShowCACertificateContent] = useState<number | null>(null);
  const [successNotificationId, setSuccessNotificationId] = useState<number | null>(null);

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

  const handleSign = (id: number, override: number | null = null) => {
    setConfirmationModalData({
      queryFn: signCA,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken || "", certificate_authority_id: override ? override : auth.activeCA?.id },
      queryKey: "cas",
      closeFn: () => setConfirmationModalData(null),
      buttonConfirmText: "Sign",
      warningText: "Signing a CSR will create a new certificate and replace the old one. This action cannot be undone.",
    });
  };

  const handleRevoke = (id: number) => {
    if (id === auth.activeCA?.id) {
      auth.setActiveCA(null);
    }
    setConfirmationModalData({
      queryFn: revokeCA,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken || "" },
      queryKey: "cas",
      closeFn: () => setConfirmationModalData(null),
      buttonConfirmText: "Revoke",
      warningText: "Revoking a CA Certificate will prevent signing CSR's and issueing a new CRL with this CA. This action cannot be undone.",
    });
  };

  const handleMakeLegacy = (id: number) => {
    if (id === auth.activeCA?.id) {
      auth.setActiveCA(null);
    }
    setConfirmationModalData({
      queryFn: makeCALegacy,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken || "" },
      queryKey: "cas",
      closeFn: () => setConfirmationModalData(null),
      buttonConfirmText: "Continue",
      warningText: "Making a CA Certificate Legacy will prevent signing CSR's with or renewing the CA certificate, but will not revoke any signed certificates. This action cannot be undone.",
    });
  }

  const handleDelete = (id: number) => {
    if (id === auth.activeCA?.id) {
      auth.setActiveCA(null);
    }
    setConfirmationModalData({
      queryFn: deleteCA,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken || "" },
      closeFn: () => setConfirmationModalData(null),
      queryKey: "cas",
      warningText: "Deleting a Certificate Authority means this row will be completely removed from the application. This action cannot be undone.",
      buttonConfirmText: "Delete",
    });
  };

  const handleExpand = (id: number, type: 'CSR' | 'Cert') => {
    if (type === 'CSR') {
      setShowCACSRContent(id === showCACSRContent ? null : id);
      setShowCACertificateContent(null);
    } else {
      setShowCACertificateContent(id === showCACertificateContent ? null : id);
      setShowCACSRContent(null);
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

  const carows = rows.map((caEntry) => {
    const csrObj = extractCSR(caEntry.csr);
    const certs = splitBundle(caEntry.certificate);
    const clientCertificate = certs?.at(0);
    const certObj = clientCertificate ? extractCert(clientCertificate) : null;

    const isSelfSigned = certs.length == 1;
    const isCSRContentVisible = showCACSRContent === caEntry.id;
    const isCertContentVisible = showCACertificateContent === caEntry.id;

    return {
      sortData: {
        id: caEntry.id,
        common_name: csrObj.commonName,
        ca_status: caEntry.status,
        cert_expiry_date: certObj?.notAfter || "",
      },
      columns: [
        { content: caEntry.id.toString() },
        { content: isSelfSigned ? "Self Signed" : "Intermediate" },
        { content: csrObj.commonName || "N/A" },
        { content: caEntry.status + (auth.activeCA?.id === caEntry.id ? " (selected)" : "") },
        {
          content: certObj?.notAfter || "",
          style: { backgroundColor: getExpiryColor(certObj?.notAfter) },
        },
        {
          content: (
            <>
              {successNotificationId === caEntry.id && <SuccessNotification successMessage="CSR copied to clipboard" />}
              <ContextualMenu
                hasToggleIcon
                position="right"
              >
                {!isSelfSigned && caEntry.status !== "legacy" &&
                  <span className="p-contextual-menu__group">
                    <Button
                      className="p-contextual-menu__link"
                      onMouseDown={() => handleExpand(caEntry.id, 'CSR')}>
                      {isCSRContentVisible ? "Hide CSR Content" : "Show CSR Content"}
                    </Button>
                    <Button
                      className="p-contextual-menu__link"
                      onMouseDown={() => handleCopy(caEntry.csr, caEntry.id)}>
                      Copy CSR to Clipboard
                    </Button>
                    <Button
                      className="p-contextual-menu__link"
                      onMouseDown={() => handleDownload(caEntry.csr, caEntry.id, csrObj)}>
                      Download CSR
                    </Button>
                  </span>
                }
                {caEntry.certificate != "" &&
                  <span className="p-contextual-menu__group">
                    <Button
                      className="p-contextual-menu__link"
                      disabled={caEntry.status == "pending"}
                      onMouseDown={() => handleExpand(caEntry.id, 'Cert')}>
                      {isCertContentVisible ? "Hide Certificate Content" : "Show Certificate Content"}
                    </Button>
                    {!isSelfSigned &&
                      <Button
                        className="p-contextual-menu__link"
                        disabled={auth.activeCA == null}
                        onMouseDown={() => handleSign(caEntry.id)}>
                        {caEntry.status === "active" ? "Re-sign CSR" : "Sign CSR"}
                      </Button>
                    }
                    {isSelfSigned && caEntry.status === "active" &&
                      <Button
                        className="p-contextual-menu__link"
                        onMouseDown={() => handleSign(caEntry.id, caEntry.id)}>
                        Renew Certificate
                      </Button>
                    }
                    {!isSelfSigned &&
                      <Button
                        className="p-contextual-menu__link"
                        onMouseDown={() => {
                          setCertificateFormOpen(true);
                          setSelectedCA(caEntry);
                        }}>
                        Upload New Certificate
                      </Button>
                    }
                    {!isSelfSigned &&
                      <Button
                        className="p-contextual-menu__link"
                        disabled={caEntry.status == "pending"}
                        onMouseDown={() => handleRevoke(caEntry.id)}>
                        Revoke Certificate
                      </Button>
                    }
                  </span>
                }
                <span className="p-contextual-menu__group">
                  {caEntry.status === "active" &&
                    <Button
                      className="p-contextual-menu__link"
                      disabled={caEntry.status != "active" || auth.activeCA?.id === caEntry.id}
                      onMouseDown={() => {
                        auth.setActiveCA(caEntry);
                      }}>
                      Select CA for Signing
                    </Button>
                  }
                  {caEntry.status === "active" &&
                    <Button
                      className="p-contextual-menu__link"
                      onMouseDown={() => handleMakeLegacy(caEntry.id)}>
                      Make CA Legacy
                    </Button>
                  }
                  <Button
                    className="p-contextual-menu__link"
                    onMouseDown={() => console.log("TODO")}>
                    Revoke All Signed Certificates
                  </Button>
                  <Button
                    className="p-contextual-menu__link"
                    onMouseDown={() => handleDelete(caEntry.id)}>
                    Delete Certificate Authority
                  </Button>
                </span>
              </ContextualMenu>
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
      title="Certificate Authorities"
      className="u-fixed-width"
      controls={rows.length > 0 && (
        <Button appearance="positive" onClick={() => setAsideOpen(true)}>
          Add New CA
        </Button>
      )}
    >
      <MainTable
        emptyStateMsg={<CAEmptyState setAsideOpen={setAsideOpen} />}
        expanding
        sortable
        headers={[
          {
            content: "ID",
            sortKey: "id",
          },
          {
            content: "CA Type",
            sortKey: "type",
          },
          {
            content: "Common Name",
            sortKey: "common_name",
          },
          {
            content: "CA Status",
            sortKey: "ca_status",
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
        rows={carows}
      />
      {confirmationModalData && (
        <NotaryConfirmationModal {...confirmationModalData} />
      )}
      {certificateFormOpen && selectedCA && (
        <SubmitCertificateModal
          id={selectedCA.id.toString()}
          csr={selectedCA.csr}
          cert={selectedCA.certificate}
          setFormOpen={setCertificateFormOpen}
        />
      )}
    </Panel>
  );
}

function CAEmptyState({ setAsideOpen }: { setAsideOpen: Dispatch<SetStateAction<boolean>> }) {
  return (
    <EmptyState
      image={""}
      title="No Certificate Authorities available yet."
    >
      <p>
        There are no Certificate Authorities in Notary. Create your first one to start signing certificates!
      </p>
      <Button
        appearance="positive"
        aria-label="add-ca-button"
        onClick={() => setAsideOpen(true)}>
        Add New Certificate Authority
      </Button>
    </EmptyState>
  );
}
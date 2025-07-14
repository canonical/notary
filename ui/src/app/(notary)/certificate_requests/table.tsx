import { useState, Dispatch, SetStateAction } from "react";
import { CertificateSigningRequest, CSREntry } from "@/types";
import {
  Button,
  MainTable,
  Panel,
  EmptyState,
  ContextualMenu,
} from "@canonical/react-components";
import { deleteCSR, rejectCSR, revokeCertificate, signCSR } from "@/queries";
import { extractCSR, extractCert, splitBundle } from "@/utils";
import { SubmitCertificateModal, SuccessNotification } from "./components";
import {
  NotaryConfirmationModal,
  NotaryConfirmationModalData,
} from "@/components/NotaryConfirmationModal";
import { useAuth } from "@/hooks/useAuth";
import { RoleID } from "@/types";

type TableProps = {
  csrs: CSREntry[];
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
};

export function CertificateRequestsTable({
  csrs: rows,
  setAsideOpen,
}: TableProps) {
  const auth = useAuth();
  const [certificateFormOpen, setCertificateFormOpen] =
    useState<boolean>(false);
  const [confirmationModalData, setConfirmationModalData] =
    // eslint-disable-next-line
    useState<NotaryConfirmationModalData<any> | null>(null);
  const [selectedCSR, setSelectedCSR] = useState<CSREntry | null>(null);
  const [showCSRContent, setShowCSRContent] = useState<number | null>(null);
  const [showCertContent, setShowCertContent] = useState<number | null>(null);
  const [successNotificationId, setSuccessNotificationId] = useState<
    number | null
  >(null);

  const canManageCSRs = [RoleID.Admin, RoleID.CertificateManager, RoleID.CertificateRequestor].includes(
    auth.user?.role_id as RoleID
  );


  const canManageCertificates = [RoleID.Admin, RoleID.CertificateManager].includes(
    auth.user?.role_id as RoleID
  );

  const handleCopy = (csr: string, id: number) => {
    void navigator.clipboard.writeText(csr).then(() => {
      setSuccessNotificationId(id);
      setTimeout(() => setSuccessNotificationId(null), 2500);
    });
  };

  const handleDownload = (
    csr: string,
    id: number,
    csrObj: CertificateSigningRequest,
  ) => {
    const blob = new Blob([csr], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `csr-${csrObj.commonName?.toLowerCase() || id}.pem`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const handleSign = (id: number) => {
    if (!auth.activeCA) {
      return;
    }
    const certs = splitBundle(auth.activeCA.certificate);
    const clientCertificate = certs?.at(0);
    const certObj = clientCertificate ? extractCert(clientCertificate) : null;
    setConfirmationModalData({
      queryFn: signCSR,
      queryParams: {
        id: id.toString(),
        authToken: auth.user?.authToken,
        certificate_authority_id: auth.activeCA.id,
      },
      closeFn: () => setConfirmationModalData(null),
      queryKey: "csrs",
      warningText: `Signing a Certificate Request means the CSR will be signed and a certificate will be generated. This CSR will be signed by "${certObj?.commonName}". This action cannot be undone.`,
      buttonConfirmText: "Sign",
    });
  };

  const handleReject = (id: number) => {
    setConfirmationModalData({
      queryFn: rejectCSR,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken },
      closeFn: () => setConfirmationModalData(null),
      queryKey: "csrs",
      warningText:
        "Rejecting a Certificate Request means the CSR will remain in this application, but its status will be moved to rejected and the associated certificate will be deleted if there is any. This action cannot be undone.",
      buttonConfirmText: "Reject",
    });
  };

  const handleDelete = (id: number) => {
    setConfirmationModalData({
      queryFn: deleteCSR,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken },
      closeFn: () => setConfirmationModalData(null),
      queryKey: "csrs",
      warningText:
        "Deleting a Certificate Request means this row will be completely removed from the application. This action cannot be undone.",
      buttonConfirmText: "Delete",
    });
  };

  const handleRevoke = (id: number) => {
    setConfirmationModalData({
      queryFn: revokeCertificate,
      queryParams: { id: id.toString(), authToken: auth.user?.authToken },
      closeFn: () => setConfirmationModalData(null),
      queryKey: "csrs",
      warningText:
        "Revoking a Certificate will delete it from the table. This action cannot be undone.",
      buttonConfirmText: "Revoke",
    });
  };

  const handleExpand = (id: number, type: "CSR" | "Cert") => {
    if (type === "CSR") {
      setShowCSRContent(id === showCSRContent ? null : id);
      setShowCertContent(null);
    } else {
      setShowCertContent(id === showCertContent ? null : id);
      setShowCSRContent(null);
    }
  };

  const getExpiryColor = (notAfter?: string): string => {
    if (!notAfter) return "inherit";
    const expiryDate = new Date(notAfter);
    const now = new Date();
    const timeDifference = expiryDate.getTime() - now.getTime();
    if (timeDifference < 0) return "rgba(199, 22, 43, 1)";
    if (timeDifference < 24 * 60 * 60 * 1000) return "rgba(249, 155, 17, 0.45)";
    return "rgba(14, 132, 32, 0.35)";
  };

  const getFieldDisplay = (
    label: string,
    field: string | undefined,
    compareField?: string,
  ) => {
    const isMismatched = compareField !== undefined && compareField !== field;
    return field ? (
      <p style={{ marginBottom: "4px" }}>
        <b>{label}:</b>{" "}
        <span
          style={{ color: isMismatched ? "rgba(199, 22, 43, 1)" : "inherit" }}
        >
          {field}
        </span>
      </p>
    ) : null;
  };
  const csrrows = rows.map((csrEntry) => {
    const { id, csr, certificate_chain, status: csr_status } = csrEntry;
    const csrObj = extractCSR(csr);
    const certs = splitBundle(certificate_chain);
    const clientCertificate = certs?.at(0);
    const certObj = clientCertificate ? extractCert(clientCertificate) : null;

    const isCSRContentVisible = showCSRContent === id;
    const isCertContentVisible = showCertContent === id;

    return {
      sortData: {
        id,
        common_name: csrObj.commonName,
        csr_status: csr_status,
        cert_expiry_date: certObj?.notAfter || "",
        username: csrEntry.username,
      },
      columns: [
        { content: id.toString() },
        { content: csrObj.commonName || "N/A" },
        { content: csr_status },
        {
          content: certObj?.notAfter || "",
          style: { backgroundColor: getExpiryColor(certObj?.notAfter) },
        },
        {
          content: csrEntry.username,
        },
        {
          content: (
            <>
              {successNotificationId === id && (
                <SuccessNotification successMessage="CSR copied to clipboard" />
              )}
              <ContextualMenu hasToggleIcon position="right">
                <span className="p-contextual-menu__group">
                  <Button
                    className="p-contextual-menu__link"
                    onClick={() => handleExpand(id, "CSR")}
                  >
                    {isCSRContentVisible
                      ? "Hide CSR Content"
                      : "Show CSR Content"}
                  </Button>
                  <Button
                    className="p-contextual-menu__link"
                    onClick={() => handleCopy(csr, id)}
                  >
                    Copy CSR to Clipboard
                  </Button>
                  <Button
                    className="p-contextual-menu__link"
                    onClick={() => handleDownload(csr, id, csrObj)}
                  >
                    Download CSR
                  </Button>
                </span>
                {canManageCertificates && (
                  <span className="p-contextual-menu__group">
                    <Button
                      className="p-contextual-menu__link"
                      disabled={csr_status == "Rejected"}
                      onClick={() => handleReject(id)}
                    >
                      Reject Certificate Request
                    </Button>
                    <Button
                      className="p-contextual-menu__link"
                      onClick={() => handleDelete(id)}
                    >
                      Delete Certificate Request
                    </Button>
                  </span>
                )}
                <span className="p-contextual-menu__group">
                  <Button
                    className="p-contextual-menu__link"
                    disabled={csr_status != "Active"}
                    onClick={() => handleExpand(id, "Cert")}
                  >
                    {isCertContentVisible
                      ? "Hide Certificate Content"
                      : "Show Certificate Content"}
                  </Button>
                  {canManageCertificates && (
                    <>
                      <Button
                        className="p-contextual-menu__link"
                        disabled={!auth.activeCA}
                        onClick={() => handleSign(id)}
                      >
                        Sign CSR
                      </Button>
                      <Button
                        className="p-contextual-menu__link"
                        disabled={csr_status != "Active"}
                        onClick={() => handleRevoke(id)}
                      >
                        Revoke Certificate
                      </Button>
                    </>
                  )}
                  {canManageCertificates && (
                    <Button
                      className="p-contextual-menu__link"
                      onClick={() => {
                        setCertificateFormOpen(true);
                        setSelectedCSR(csrEntry);
                      }}
                    >
                      Upload New Certificate
                    </Button>

                  )}
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
        <div>
          {isCSRContentVisible && (
            <div>
              <h4>Certificate Request Content</h4>
              {getFieldDisplay("Common Name", csrObj.commonName)}
              {getFieldDisplay(
                "Subject Alternative Name DNS",
                csrObj.sansDns?.join(", "),
              )}
              {getFieldDisplay(
                "Subject Alternative Name IP addresses",
                csrObj.sansIp?.join(", "),
              )}
              {getFieldDisplay("Country", csrObj.country)}
              {getFieldDisplay("State or Province", csrObj.stateOrProvince)}
              {getFieldDisplay("Locality", csrObj.locality)}
              {getFieldDisplay("Organization", csrObj.organization)}
              {getFieldDisplay(
                "Organizational Unit",
                csrObj.OrganizationalUnitName,
              )}
              {getFieldDisplay("Email Address", csrObj.emailAddress)}
              <p>
                <b>Certificate request for a certificate authority</b>:{" "}
                {csrObj.is_ca ? "Yes" : "No"}
              </p>
            </div>
          )}
          {isCertContentVisible && certObj && (
            <div>
              <h4>Certificate Content</h4>
              {getFieldDisplay("Common Name", certObj.commonName)}
              {getFieldDisplay(
                "Subject Alternative Name DNS",
                certObj.sansDns?.join(", "),
              )}
              {getFieldDisplay(
                "Subject Alternative Name IP addresses",
                certObj.sansIp?.join(", "),
              )}
              {getFieldDisplay("Country", certObj.country)}
              {getFieldDisplay("State or Province", certObj.stateOrProvince)}
              {getFieldDisplay("Locality", certObj.locality)}
              {getFieldDisplay("Organization", certObj.organization)}
              {getFieldDisplay(
                "Organizational Unit",
                certObj.OrganizationalUnitName,
              )}
              {getFieldDisplay("Email Address", certObj.emailAddress)}
              {getFieldDisplay("Start of validity", certObj.notBefore)}
              {getFieldDisplay("Expiry Time", certObj.notAfter)}
              {getFieldDisplay("Issuer Common Name", certObj.issuerCommonName)}
              <p>
                <b>Certificate for a certificate authority</b>:{" "}
                {certObj.is_ca ? "Yes" : "No"}
              </p>
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
      controls={
        rows.length > 0 && canManageCSRs && (
          <Button appearance="positive" onClick={() => setAsideOpen(true)}>
            Add New Certificate Request
          </Button>
        )
      }
    >
      <MainTable
        emptyStateMsg={<CSREmptyState setAsideOpen={setAsideOpen} />}
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
            content: "Username",
            sortKey: "username",
          },
          {
            content: "Actions",
            className: "u-align--right has-overflow",
          },
        ]}
        rows={csrrows}
      />
      {confirmationModalData && (
        <NotaryConfirmationModal {...confirmationModalData} />
      )}
      {certificateFormOpen && selectedCSR && (
        <SubmitCertificateModal
          id={selectedCSR.id.toString()}
          csr={selectedCSR.csr}
          cert={selectedCSR.certificate_chain}
          setFormOpen={setCertificateFormOpen}
        />
      )}
    </Panel>
  );
}

function CSREmptyState({
  setAsideOpen,
}: {
  setAsideOpen: Dispatch<SetStateAction<boolean>>;
}) {
  const auth = useAuth();

  const canManageCSRs = [RoleID.Admin, RoleID.CertificateManager, RoleID.CertificateRequestor].includes(
    auth.user?.role_id as RoleID
  );

  return (
    <EmptyState image={""} title="No CSRs available yet.">
      <p>
        There are no Certificate Requests in Notary. Request your first
        certificate!
      </p>
      {canManageCSRs && (
        <Button
          appearance="positive"
          aria-label="add-csr-button"
          onClick={() => setAsideOpen(true)}
        >
          Add New CSR
        </Button>
      )}
    </EmptyState>
  );
}

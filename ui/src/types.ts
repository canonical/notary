export type CSREntry = {
  id: number;
  csr: string;
  certificate_chain: string;
  status: "Outstanding" | "Active" | "Rejected" | "Revoked";
  username: string;
};

export type CertificateSigningRequest = {
  commonName?: string;
  stateOrProvince?: string;
  OrganizationalUnitName?: string;
  organization?: string;
  emailAddress?: string;
  country?: string;
  locality?: string;
  sansDns: string[];
  sansIp: string[];
  is_ca: boolean;
};

export type CertificateAuthorityEntry = {
  id: number;
  enabled: boolean;
  certificate: string;
  csr: string;
  crl: string;
};

export type User = {
  exp: number;
  id: number;
  role_id: number;
  username: string;
  authToken: string;

  activeCA: number;
};

export type UserEntry = {
  id: number;
  username: string;
};

export type AsideFormData = {
  formTitle: string;
  user?: {
    id: string;
    username: string;
  };
};

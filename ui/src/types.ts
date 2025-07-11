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

export enum RoleID {
  Admin = 0,
  CertificateManager = 1,
}

export type User = {
  exp: number;
  id: number;
  role_id: RoleID;
  username: string;
  authToken: string;
  activeCA: number;
};

export type UserEntry = {
  id: number;
  username: string;
  role_id: RoleID;
};

export type AsideFormData = {
  formTitle: string;
  user?: {
    id: string;
    username: string;
  };
};

export type APIResponse<T = undefined> = {
  message?: string;
  data?: T;
};

export type APIErrorResponse = APIResponse<undefined> & {
  message: string;
};

export class APIError extends Error {
  status: number;
  statusText: string;
  responseMessage: string;

  constructor(status: number, statusText: string, responseMessage = "") {
    super(responseMessage || `${status}: ${statusText}`);
    this.name = "APIError";
    this.status = status;
    this.statusText = statusText;
    this.responseMessage = responseMessage;
  }
}

export type CSREntry = {
  id: number;
  csr: string;
  certificate_chain: string;
  status: "Outstanding" | "Active" | "Rejected" | "Revoked";
  email: string;
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
  CertificateRequestor = 2,
  ReadOnly = 3,
}

export type User = {
  exp: number;
  id: number;
  role_id: RoleID;
  email: string;
  activeCA: number;
};

export type UserEntry = {
  id: number;
  email: string;
  role_id: RoleID;
};

export type ConfigEntry = {
  port: number;
  pebble_notifications: boolean;
  logging_level: string;
  logging_output: string;
  encryption_backend_type: string;
};

export type AsideFormData = {
  formTitle: string;
  user?: {
    id: string;
    email: string;
  };
};

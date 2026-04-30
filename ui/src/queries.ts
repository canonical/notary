/* eslint-disable */

import {
  APIError,
  APIErrorResponse,
  APIResponse,
  CertificateAuthorityEntry,
  ConfigEntry,
  CSREntry,
  UserEntry,
} from "@/types";
import { HTTPStatus } from "@/utils";

export type RequiredCSRParams = {
  id: string;
  csr?: string;
  cert?: string;
};

export type RequiredCAParams = {
  id: string;
};

type GETStatus = {
  initialized: boolean;
  version: string;
  oidc_enabled: boolean;
};

async function parseAPIResponse<T>(response: globalThis.Response) {
  const respData = (await response.json()) as APIResponse<T> | APIErrorResponse;

  if (!response.ok) {
    const errorResponse = respData as APIErrorResponse;
    throw new APIError(
      response.status,
      HTTPStatus(response.status),
      errorResponse.message ?? "",
    );
  }

  return respData as APIResponse<T>;
}

async function fetchAPI<T>(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<T | undefined> {
  const response = await fetch(input, init);
  const respData = await parseAPIResponse<T>(response);
  return respData.data;
}

export async function getStatus(): Promise<GETStatus> {
  return (await fetchAPI<GETStatus>("/status")) as GETStatus;
}

export async function getCertificateRequests(): Promise<CSREntry[]> {
  return (await fetchAPI<CSREntry[]>(
    "/api/v1/certificate_requests",
  )) as CSREntry[];
}

export async function postCSR(params: { csr: string }) {
  if (!params.csr) {
    throw new Error("CSR not provided");
  }
  const reqParams = {
    csr: params.csr.trim(),
  };
  return fetchAPI<{ id: number }>("/api/v1/certificate_requests", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
}

export async function postCertToID(params: RequiredCSRParams) {
  if (!params.cert) {
    throw new Error("Certificate not provided");
  }
  const reqParams = {
    certificate: params.cert.trim(),
  };
  return fetchAPI(
    "/api/v1/certificate_requests/" + params.id + "/certificate",
    {
      method: "post",
      headers: {
        "Content-Type": "text/plain",
      },
      body: JSON.stringify(reqParams),
    },
  );
}

export async function deleteCSR(params: RequiredCSRParams) {
  return fetchAPI("/api/v1/certificate_requests/" + params.id, {
    method: "delete",
  });
}

export async function signCSR(
  params: RequiredCSRParams & { certificate_authority_id: number },
) {
  if (!params.certificate_authority_id) {
    throw new Error("Certificate not provided");
  }
  const reqParams = {
    certificate_authority_id: params.certificate_authority_id.toString(),
  };
  return fetchAPI("/api/v1/certificate_requests/" + params.id + "/sign", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
}

export async function rejectCSR(params: RequiredCSRParams) {
  return fetchAPI("/api/v1/certificate_requests/" + params.id + "/reject", {
    method: "post",
  });
}

export async function revokeCertificate(params: RequiredCSRParams) {
  return fetchAPI(
    "/api/v1/certificate_requests/" + params.id + "/certificate/revoke",
    {
      method: "post",
    },
  );
}

export async function login(userForm: { email: string; password: string }) {
  return fetchAPI("/login", {
    method: "POST",

    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
    }),
  });
}

export async function logout() {
  return fetchAPI("/logout", { method: "POST" });
}

export async function changeSelfPassword(changePasswordForm: {
  password: string;
}) {
  return fetchAPI("/api/v1/accounts/me/change_password", {
    method: "POST",
    body: JSON.stringify({ password: changePasswordForm.password }),
  });
}

export async function changePassword(changePasswordForm: {
  id: string;
  password: string;
}) {
  return fetchAPI(
    "/api/v1/accounts/" + changePasswordForm.id + "/change_password",
    {
      method: "POST",
      body: JSON.stringify({ password: changePasswordForm.password }),
    },
  );
}

export async function ListUsers(params: {}): Promise<UserEntry[]> {
  return (await fetchAPI<UserEntry[]>("/api/v1/accounts")) as UserEntry[];
}

export async function getSelfAccount(): Promise<UserEntry> {
  return (await fetchAPI<UserEntry>("/api/v1/accounts/me")) as UserEntry;
}

export async function deleteUser(params: { id: string }) {
  return fetchAPI("/api/v1/accounts/" + params.id, {
    method: "delete",
  });
}

export async function updateUserRole(params: { id: string; role_id: number }) {
  const response = await fetch("/api/v1/accounts/" + params.id + "/role", {
    method: "PUT",
    body: JSON.stringify({ role_id: params.role_id }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function postFirstUser(userForm: {
  email: string;
  password: string;
  role_id: number;
}) {
  return fetchAPI<{ id: number }>("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
      role_id: userForm.role_id,
    }),
  });
}

export async function postUser(userForm: {
  email: string;
  password: string;
  role_id: number;
}) {
  return fetchAPI<{ id: number }>("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
      role_id: userForm.role_id,
    }),
  });
}

export async function getCertificateAuthorities(): Promise<
  CertificateAuthorityEntry[]
> {
  return (await fetchAPI<CertificateAuthorityEntry[]>(
    "/api/v1/certificate_authorities",
  )) as CertificateAuthorityEntry[];
}

export async function postCA(params: {
  SelfSigned: boolean;
  CommonName: string;
  CountryName: string;
  StateOrProvinceName: string;
  LocalityName: string;
  OrganizationName: string;
  OrganizationalUnit: string;
  NotValidAfter: string;
}) {
  const NotValidAfterDate =
    params.NotValidAfter !== "" ? new Date(params.NotValidAfter) : null;
  const reqParams = {
    self_signed: params.SelfSigned,
    common_name: params.CommonName,
    sans_dns: "",
    country_name: params.CountryName,
    state_or_province_name: params.StateOrProvinceName,
    locality_name: params.LocalityName,
    organization_name: params.OrganizationName,
    organizational_unit_name: params.OrganizationalUnit,
    not_valid_after: NotValidAfterDate?.toISOString(),
  };
  return fetchAPI<{ id: number }>("/api/v1/certificate_authorities", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
}

export async function deleteCA(params: RequiredCAParams) {
  return fetchAPI("/api/v1/certificate_authorities/" + params.id, {
    method: "delete",
  });
}

export async function revokeCA(params: RequiredCAParams) {
  return fetchAPI("/api/v1/certificate_authorities/" + params.id + "/revoke", {
    method: "post",
  });
}

export async function disableCA(params: RequiredCAParams) {
  return fetchAPI("/api/v1/certificate_authorities/" + params.id, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ enabled: false }),
  });
}

export async function postCertToCA(
  params: RequiredCAParams & { certificate_chain: string },
) {
  if (!params.certificate_chain) {
    throw new Error("Certificate not provided");
  }
  const reqParams = {
    certificate_chain: params.certificate_chain.trim(),
  };
  return fetchAPI(
    "/api/v1/certificate_authorities/" + params.id + "/certificate",
    {
      method: "post",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(reqParams),
    },
  );
}

export async function signCA(
  params: RequiredCAParams & { certificate_authority_id: number },
) {
  if (!params.certificate_authority_id) {
    throw new Error("Certificate not provided");
  }
  const reqParams = {
    certificate_authority_id: params.certificate_authority_id.toString(),
  };
  return fetchAPI("/api/v1/certificate_authorities/" + params.id + "/sign", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
}

export async function getConfig(): Promise<ConfigEntry> {
  return (await fetchAPI<ConfigEntry>("/api/v1/config")) as ConfigEntry;
}

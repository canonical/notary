// FIXME: Update the response and param types to match the actual API response when they are standardized
/* eslint-disable */

import { CertificateAuthorityEntry, CSREntry, UserEntry } from "@/types";
import { HTTPStatus } from "@/utils";

export type RequiredCSRParams = {
  id: string;
  csr?: string;
  cert?: string;
};

export type RequiredCAParams = {
  id: string;
};

export type Response<T> = {
  result: T;
  error: string;
};

type GETStatus = {
  initialized: boolean;
  version: string;
};

export async function getStatus(): Promise<GETStatus> {
  const response = await fetch("/status");
  const respData = (await response.json()) as Response<GETStatus>;
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function getCertificateRequests(): Promise<CSREntry[]> {
  const response = await fetch("/api/v1/certificate_requests");
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function postCSR(params: { csr: string }) {
  if (!params.csr) {
    throw new Error("CSR not provided");
  }
  const reqParams = {
    csr: params.csr.trim(),
  };
  const response = await fetch("/api/v1/certificate_requests", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function postCertToID(params: RequiredCSRParams) {
  if (!params.cert) {
    throw new Error("Certificate not provided");
  }
  const reqParams = {
    certificate: params.cert.trim(),
  };
  const response = await fetch(
    "/api/v1/certificate_requests/" + params.id + "/certificate",
    {
      method: "post",
      headers: {
        "Content-Type": "text/plain",
      },
      body: JSON.stringify(reqParams),
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function deleteCSR(params: RequiredCSRParams) {
  const response = await fetch("/api/v1/certificate_requests/" + params.id, {
    method: "delete",
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
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
  const response = await fetch(
    "/api/v1/certificate_requests/" + params.id + "/sign",
    {
      method: "post",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(reqParams),
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function rejectCSR(params: RequiredCSRParams) {
  const response = await fetch(
    "/api/v1/certificate_requests/" + params.id + "/reject",
    { method: "post" },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function revokeCertificate(params: RequiredCSRParams) {
  const response = await fetch(
    "/api/v1/certificate_requests/" + params.id + "/certificate/revoke",
    {
      method: "post",
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function login(userForm: { email: string; password: string }) {
  const response = await fetch("/login", {
    method: "POST",

    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
    }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function logout() {
  const response = await fetch("/logout", { method: "POST" });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function changeSelfPassword(changePasswordForm: {
  password: string;
}) {
  const response = await fetch("/api/v1/accounts/me/change_password", {
    method: "POST",
    body: JSON.stringify({ password: changePasswordForm.password }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function changePassword(changePasswordForm: {
  id: string;
  password: string;
}) {
  const response = await fetch(
    "/api/v1/accounts/" + changePasswordForm.id + "/change_password",
    {
      method: "POST",
      body: JSON.stringify({ password: changePasswordForm.password }),
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function ListUsers(params: {}): Promise<UserEntry[]> {
  const response = await fetch("/api/v1/accounts");
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function getSelfAccount(): Promise<UserEntry> {
  const response = await fetch("/api/v1/accounts/me");
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function deleteUser(params: { id: string }) {
  const response = await fetch("/api/v1/accounts/" + params.id, {
    method: "delete",
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
  const response = await fetch("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
      role_id: userForm.role_id,
    }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function postUser(userForm: {
  email: string;
  password: string;
  role_id: number;
}) {
  const response = await fetch("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      email: userForm.email,
      password: userForm.password,
      role_id: userForm.role_id,
    }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function getCertificateAuthorities(): Promise<
  CertificateAuthorityEntry[]
> {
  const response = await fetch("/api/v1/certificate_authorities");
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
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
  const response = await fetch("/api/v1/certificate_authorities", {
    method: "post",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reqParams),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function deleteCA(params: RequiredCAParams) {
  const response = await fetch("/api/v1/certificate_authorities/" + params.id, {
    method: "delete",
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function revokeCA(params: RequiredCAParams) {
  const response = await fetch(
    "/api/v1/certificate_authorities/" + params.id + "/revoke",
    {
      method: "post",
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function disableCA(params: RequiredCAParams) {
  const response = await fetch("/api/v1/certificate_authorities/" + params.id, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ enabled: false }),
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
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
  const response = await fetch(
    "/api/v1/certificate_authorities/" + params.id + "/certificate",
    {
      method: "post",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(reqParams),
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
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
  const response = await fetch(
    "/api/v1/certificate_authorities/" + params.id + "/sign",
    {
      method: "post",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(reqParams),
    },
  );
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

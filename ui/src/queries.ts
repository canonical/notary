// FIXME: Update the response and param types to match the actual API response when they are standardized
/* eslint-disable */

import { CertificateAuthorityEntry, CSREntry, UserEntry } from "@/types";
import { HTTPStatus } from "@/utils";

export type RequiredCSRParams = {
  id: string;
  authToken: string;
  csr?: string;
  cert?: string;
};

export type RequiredCAParams = {
  id: string;
  authToken: string;
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

export async function getCertificateRequests(params: {
  authToken: string;
}): Promise<CSREntry[]> {
  const response = await fetch("/api/v1/certificate_requests", {
    headers: { Authorization: "Bearer " + params.authToken },
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  console.log(respData);
  return respData.result;
}

export async function postCSR(params: { authToken: string; csr: string }) {
  if (!params.csr) {
    throw new Error("CSR not provided");
  }
  const reqParams = {
    csr: params.csr.trim(),
  };
  const response = await fetch("/api/v1/certificate_requests", {
    method: "post",
    headers: {
      "Content-Type": "text/plain",
      Authorization: "Bearer " + params.authToken,
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
        Authorization: "Bearer " + params.authToken,
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
    headers: {
      Authorization: "Bearer " + params.authToken,
    },
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
        Authorization: "Bearer " + params.authToken,
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
    {
      method: "post",
      headers: {
        Authorization: "Bearer " + params.authToken,
      },
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

export async function revokeCertificate(params: RequiredCSRParams) {
  const response = await fetch(
    "/api/v1/certificate_requests/" + params.id + "/certificate/revoke",
    {
      method: "post",
      headers: {
        Authorization: "Bearer " + params.authToken,
      },
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

export async function login(userForm: {
  username: string;
  password: string;
}): Promise<{ token: string }> {
  const response = await fetch("/login", {
    method: "POST",

    body: JSON.stringify({
      username: userForm.username,
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

export async function changeSelfPassword(changePasswordForm: {
  authToken: string;
  password: string;
}) {
  const response = await fetch("/api/v1/accounts/me/change_password", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + changePasswordForm.authToken,
    },
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
  authToken: string;
  id: string;
  password: string;
}) {
  const response = await fetch(
    "/api/v1/accounts/" + changePasswordForm.id + "/change_password",
    {
      method: "POST",
      headers: {
        Authorization: "Bearer " + changePasswordForm.authToken,
      },
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

export async function ListUsers(params: {
  authToken: string;
}): Promise<UserEntry[]> {
  const response = await fetch("/api/v1/accounts", {
    headers: { Authorization: "Bearer " + params.authToken },
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function deleteUser(params: { authToken: string; id: string }) {
  const response = await fetch("/api/v1/accounts/" + params.id, {
    method: "delete",
    headers: {
      Authorization: "Bearer " + params.authToken,
    },
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
  username: string;
  password: string;
}) {
  const response = await fetch("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      username: userForm.username,
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

export async function postUser(userForm: {
  authToken: string;
  username: string;
  password: string;
}) {
  const response = await fetch("/api/v1/accounts", {
    method: "POST",
    body: JSON.stringify({
      username: userForm.username,
      password: userForm.password,
    }),
    headers: {
      Authorization: "Bearer " + userForm.authToken,
    },
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function getCertificateAuthorities(params: {
  authToken: string;
}): Promise<CertificateAuthorityEntry[]> {
  const response = await fetch("/api/v1/certificate_authorities", {
    headers: { Authorization: "Bearer " + params.authToken },
  });
  const respData = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status}: ${HTTPStatus(response.status)}. ${respData.error}`,
    );
  }
  return respData.result;
}

export async function postCA(params: {
  authToken: string;

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
      Authorization: "Bearer " + params.authToken,
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
    headers: {
      Authorization: "Bearer " + params.authToken,
    },
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
      headers: {
        Authorization: "Bearer " + params.authToken,
      },
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

export async function makeCALegacy(params: RequiredCAParams) {
  const response = await fetch("/api/v1/certificate_authorities/" + params.id, {
    method: "PUT",
    headers: {
      Authorization: "Bearer " + params.authToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ status: "legacy" }),
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
        Authorization: "Bearer " + params.authToken,
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
        Authorization: "Bearer " + params.authToken,
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

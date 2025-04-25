import {
  CertificationRequest,
  Certificate,
  Extensions,
  CertificateChainValidationEngine,
} from "pkijs";
import { fromBER } from "asn1js";
import * as pvutils from "pvutils";
import { CertificateSigningRequest } from "./types";

export const oidToName = (oid: string) => {
  const map: { [key: string]: string } = {
    // Subject OID's
    "2.5.4.3": "Common Name",
    "2.5.4.6": "Country",
    "2.5.4.7": "Locality",
    "2.5.4.8": "State or Province",
    "2.5.4.9": "Street Address",
    "2.5.4.97": "Organization Identifier",
    "2.5.4.10": "Organization Name",
    "2.5.4.11": "Organizational Unit Name",
    "2.5.4.5": "Serial Number",
    "2.5.4.4": "Surname",
    "2.5.4.42": "Given Name",
    "2.5.4.12": "Title",
    "2.5.4.43": "Initials",
    "2.5.4.44": "Generation Qualifier",
    "2.5.4.45": "X500 Unique Identifier",
    "2.5.4.46": "Dn Qualifier",
    "2.5.4.65": "Pseudonym",
    "0.9.2342.19200300.100.1.1": "User Id",
    "0.9.2342.19200300.100.1.25": "Domain Component",
    "1.2.840.113549.1.9.1": "Email Address",
    "1.3.6.1.4.1.311.60.2.1.3": "Jurisdiction Country-Name",
    "1.3.6.1.4.1.311.60.2.1.1": "Jurisdiction Locality-Name",
    "1.3.6.1.4.1.311.60.2.1.2": "Jurisdiction State Or Province Name",
    "2.5.4.15": "Business Category",
    "2.5.4.16": "Postal Address",
    "2.5.4.17": "Postal Code",
    "1.2.643.3.131.1.1": "Inn",
    "1.2.643.100.1": "Ogrn",
    "1.2.643.100.3": "Snils",
    "1.2.840.113549.1.9.2": "Unstructured Name",
    // OID for pkcs-9-at-extensionRequest
    "1.2.840.113549.1.9.14": "Extension Request",
    // OID for basicConstraint
    "2.5.29.19": "Basic Constraint",
    "2.5.29.17": "Subject Alternative Name",
    //
    "2.5.29.15": "keyUsage",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.31": "cRLDistributionPoints",
  };
  if (!(oid in map)) {
    throw new Error("oid not recognized: " + oid);
  }
  return map[oid];
};

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/(-----(BEGIN|END) [A-Z ]+-----|\n|\r)/g, "");
  const binaryDerString = atob(b64);
  const binaryDer = pvutils.stringToArrayBuffer(binaryDerString);
  return binaryDer;
}

function hexToIp(hex: ArrayBuffer): string {
  const byteArray = new Uint8Array(hex);
  return Array.from(byteArray)
    .map((byte) => byte.toString(10))
    .join(".");
}

function parseExtensions(extensions: Extensions) {
  const sansDns: string[] = [];
  const sansIp: string[] = [];
  let is_ca = false;

  extensions.extensions.forEach((extension) => {
    let extensionName: string;
    try {
      extensionName = oidToName(extension.extnID);
    } catch {
      console.error(`Unrecognized extension OID: ${extension.extnID}`);
      return;
    }

    if (extensionName === "Subject Alternative Name") {
      // eslint-disable-next-line
      extension.parsedValue.altNames.forEach(
        (altName: { type: number; value: any }) => {
          if (altName.type == 2) {
            // eslint-disable-next-line
            sansDns.push(altName.value);
          } else if (altName.type == 7) {
            // eslint-disable-next-line
            sansIp.push(hexToIp(altName.value.valueBlock.valueHex));
          }
        },
      );
    } else if (extensionName === "Basic Constraint") {
      // eslint-disable-next-line
      is_ca = extension.parsedValue.cA;
    }
  });

  return { sansDns, sansIp, is_ca };
}

function loadCertificateRequest(csrPemString: string) {
  const binaryDer = pemToArrayBuffer(csrPemString);
  const asn1 = fromBER(binaryDer);
  const csr = new CertificationRequest({ schema: asn1.result });
  return csr;
}

function loadCertificate(certPemString: string) {
  const binaryDer = pemToArrayBuffer(certPemString);
  const asn1 = fromBER(binaryDer);
  if (asn1.offset === -1) {
    throw new Error("Error parsing certificate");
  }
  const cert = new Certificate({ schema: asn1.result });
  return cert;
}

export const extractCSR = (csrPemString: string): CertificateSigningRequest => {
  const csr = loadCertificateRequest(csrPemString);

  // Extract subject information from CSR
  const subjects = csr.subject.typesAndValues.map((typeAndValue) => ({
    type: oidToName(typeAndValue.type),
    value: typeAndValue.value.valueBlock.value,
  }));
  const getValue = (type: string) =>
    subjects.find((subject) => subject.type === type)?.value;

  const commonName = getValue("Common Name");
  const organization = getValue("Organization Name");
  const emailAddress = getValue("Email Address");
  const country = getValue("Country");
  const locality = getValue("Locality");
  const stateOrProvince = getValue("State or Province");
  const OrganizationalUnitName = getValue("Organizational Unit Name");

  let sansDns: string[] = [];
  let sansIp: string[] = [];
  let is_ca = false;

  if (csr.attributes) {
    const extensionAttributes = csr.attributes.filter(
      (attribute) => oidToName(attribute.type) === "Extension Request",
    );
    if (extensionAttributes.length > 0) {
      const extensions = new Extensions({
        schema: extensionAttributes[0].values[0],
      });
      ({ sansDns, sansIp, is_ca } = parseExtensions(extensions));
    }
  }
  return {
    commonName,
    stateOrProvince,
    OrganizationalUnitName,
    organization,
    emailAddress,
    country,
    locality,
    sansDns,
    sansIp,
    is_ca,
  };
};

export const csrIsValid = (csrPemString: string) => {
  try {
    extractCSR(csrPemString.trim());
    return true;
  } catch {
    return false;
  }
};

export const extractCert = (certPemString: string) => {
  if (certPemString === "" || certPemString === "rejected") {
    return null;
  }

  const cert = loadCertificate(certPemString);

  const subjects = cert.subject.typesAndValues.map((typeAndValue) => ({
    type: oidToName(typeAndValue.type),
    value: typeAndValue.value.valueBlock.value,
  }));
  const issuerInfo = cert.issuer.typesAndValues.map((typeAndValue) => ({
    type: oidToName(typeAndValue.type),
    value: typeAndValue.value.valueBlock.value,
  }));
  const getSubjectValue = (type: string) =>
    subjects.find((subject) => subject.type === type)?.value;
  const getIssuerValue = (type: string) =>
    issuerInfo.find((info) => info.type === type)?.value;

  const commonName = getSubjectValue("Common Name");
  const organization = getSubjectValue("Organization Name");
  const emailAddress = getSubjectValue("Email Address");
  const country = getSubjectValue("Country");
  const locality = getSubjectValue("Locality");
  const stateOrProvince = getSubjectValue("State or Province");
  const OrganizationalUnitName = getSubjectValue("Organizational Unit Name");
  const issuerCommonName = getIssuerValue("Common Name");
  const issuerOrganization = getIssuerValue("Organization Name");
  const issuerEmailAddress = getIssuerValue("Email Address");
  const issuerCountry = getIssuerValue("Country");
  const issuerLocality = getIssuerValue("Locality");
  const issuerStateOrProvince = getIssuerValue("State or Province");
  const issuerOrganizationalUnitName = getIssuerValue(
    "Organizational Unit Name",
  );

  const notBeforeUnformatted = cert.notBefore.value.toString();
  const notBefore = notBeforeUnformatted
    ? notBeforeUnformatted.replace(/\s*\(.+\)/, "")
    : "";
  const notAfterUnformatted = cert.notAfter.value.toString();
  const notAfter = notAfterUnformatted
    ? notAfterUnformatted.replace(/\s*\(.+\)/, "")
    : "";

  // Extract extensions such as SANs and Basic Constraints
  let sansDns: string[] = [];
  let sansIp: string[] = [];
  let is_ca = false;

  if (cert.extensions) {
    // Correctly handle extensions by creating a new Extensions object
    const extensionsInstance = new Extensions({ extensions: cert.extensions });
    const ext = parseExtensions(extensionsInstance);
    sansDns = ext.sansDns;
    sansIp = ext.sansIp;
    is_ca = ext.is_ca;
  }
  return {
    commonName,
    stateOrProvince,
    OrganizationalUnitName,
    organization,
    emailAddress,
    country,
    locality,
    sansDns,
    sansIp,
    is_ca,
    notBefore,
    notAfter,
    issuerCommonName,
    issuerOrganization,
    issuerEmailAddress,
    issuerCountry,
    issuerLocality,
    issuerStateOrProvince,
    issuerOrganizationalUnitName,
  };
};

export const csrMatchesCertificate = (
  csrPemString: string,
  certPemString: string,
) => {
  const cert = loadCertificate(certPemString);
  const csr = loadCertificateRequest(csrPemString);

  const csrPKbytes =
    csr.subjectPublicKeyInfo.subjectPublicKey.valueBeforeDecodeView;
  const certPKbytes =
    cert.subjectPublicKeyInfo.subjectPublicKey.valueBeforeDecodeView;
  return csrPKbytes.toString() == certPKbytes.toString();
};

export const HTTPStatus = (code: number): string => {
  const map: { [key: number]: string } = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
  };
  if (!(code in map)) {
    throw new Error("code not recognized: " + code);
  }
  return map[code];
};

export const passwordIsValid = (pw: string) => {
  if (pw.length < 8) return false;

  const result = {
    hasCapital: false,
    hasLowercase: false,
    hasSymbol: false,
    hasNumber: false,
  };

  if (/[A-Z]/.test(pw)) {
    result.hasCapital = true;
  }
  if (/[a-z]/.test(pw)) {
    result.hasLowercase = true;
  }
  if (/[0-9]/.test(pw)) {
    result.hasNumber = true;
  }
  if (/[^A-Za-z0-9]/.test(pw)) {
    result.hasSymbol = true;
  }

  if (
    result.hasCapital &&
    result.hasLowercase &&
    (result.hasSymbol || result.hasNumber)
  ) {
    return true;
  }
  return false;
};

export const splitBundle = (bundle: string): string[] => {
  const pemPattern =
    /-----BEGIN CERTIFICATE-----(?:.|\n)*?-----END CERTIFICATE-----/g;
  const pemMatches = bundle.match(pemPattern);
  return pemMatches ? pemMatches.map((e) => e.toString()) : [];
};

export const validateBundle = async (bundle: string) => {
  const bundleList = splitBundle(bundle);
  const extractedCerts = bundleList.map((cert) => loadCertificate(cert));
  const rootCa = extractedCerts.at(-1);
  if (rootCa == undefined) {
    return "less than 2 certificates found.";
  }
  const chainEngine = new CertificateChainValidationEngine({
    certs: extractedCerts,
    trustedCerts: [rootCa],
  });
  const result = await chainEngine.verify();
  return result.resultMessage;
};

export const retryUnlessUnauthorized = (
  failureCount: number,
  error: Error,
): boolean => {
  if (error.message.includes("401")) {
    return false;
  }
  return true;
};

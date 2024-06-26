import { CertificationRequest, Certificate } from "pkijs";
import { fromBER } from "asn1js";


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
        "2.5.29.19": "Basic Constraint"
    }
    if (!(oid in map)) {
        throw new Error("oid not recognized: " + oid)
    }
    return map[oid]
}

export const extractCSR = (csrPemString: string) => {
    // Decode PEM to DER
    const pemHeader = "-----BEGIN CERTIFICATE REQUEST-----";
    const pemFooter = "-----END CERTIFICATE REQUEST-----";
    const pemContents = csrPemString.substring(pemHeader.length, csrPemString.length - pemFooter.length);
    const binaryDerString = window.atob(pemContents);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) {
        binaryDer[i] = binaryDerString.charCodeAt(i);
    }

    // Parse DER encoded CSR
    const asn1 = fromBER(binaryDer.buffer);
    if (asn1.offset === -1) {
        throw new Error("Error parsing certificate request");
    }

    // Load CSR object
    const csr = new CertificationRequest({ schema: asn1.result });

    // Extract subject information from CSR
    const subjects = csr.subject.typesAndValues.map(typeAndValue => ({
        type: oidToName(typeAndValue.type),
        value: typeAndValue.value.valueBlock.value
    }));

    // Look for extensions attribute in CSR
    const attributes = csr.attributes?.map(typeAndValue => ({
        type: oidToName(typeAndValue.type),
        value: typeAndValue.values
    }))
    return { subjects }
}

export const extractCert = (certPemString: string) => {
    if (certPemString == "" || certPemString == "rejected") { return }
    // Decode PEM to DER
    const pemHeader = "-----BEGIN CERTIFICATE-----";
    const pemFooter = "-----END CERTIFICATE-----";
    const pemContents = certPemString.substring(pemHeader.length, certPemString.length - pemFooter.length);
    const binaryDerString = window.atob(pemContents);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) {
        binaryDer[i] = binaryDerString.charCodeAt(i);
    }

    // Parse DER encoded certificate
    const asn1 = fromBER(binaryDer.buffer);
    if (asn1.offset === -1) {
        throw new Error("Error parsing certificate");
    }

    // Load Certificate object
    const cert = new Certificate({ schema: asn1.result });

    // Extract relevant information from certificate
    const subject = cert.subject.typesAndValues.map(typeAndValue => ({
        type: typeAndValue.type,
        value: typeAndValue.value.valueBlock.value
    }));

    const issuer = cert.issuer.typesAndValues.map(typeAndValue => ({
        type: typeAndValue.type,
        value: typeAndValue.value.valueBlock.value
    }));

    const notBefore = cert.notBefore.value.toString();
    const notAfter = cert.notAfter.value.toString();

    return { notAfter }
}
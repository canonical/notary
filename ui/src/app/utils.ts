import { CertificationRequest, Certificate, Extension, Extensions, GeneralName, GeneralNames } from "pkijs";
import { fromBER } from "asn1js";
import * as pvutils from "pvutils";


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
        "2.5.29.17": "Subject Alternative Name"
    }
    if (!(oid in map)) {
        throw new Error("oid not recognized: " + oid)
    }
    return map[oid]
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const b64 = pem.replace(/(-----(BEGIN|END) [A-Z ]+-----|\n|\r)/g, "");
    const binaryDerString = atob(b64);
    const binaryDer = pvutils.stringToArrayBuffer(binaryDerString);
    return binaryDer;
}

function hexToIp(hex: ArrayBuffer): string {
    const byteArray = new Uint8Array(hex);
    return Array.from(byteArray).map(byte => byte.toString(10)).join('.');
}

function parseExtensions(extensions: Extensions) {
    const sansDns: string[] = [];
    const sansIp: string[] = [];
    let is_ca = false;

    extensions.extensions.forEach(extension => {
        let extensionName: string;
        try {
            extensionName = oidToName(extension.extnID);
        } catch (error) {
            console.error(`Unrecognized extension OID: ${extension.extnID}`);
            return;
        }

        if (extensionName === "Subject Alternative Name") {
            extension.parsedValue.altNames.forEach((altName: { type: number; value: any; }) => {
                if (altName.type == 2) {
                    sansDns.push(altName.value);
                } else if (altName.type == 7) {
                    sansIp.push(hexToIp(altName.value.valueBlock.valueHex));
                }
            });
        } else if (extensionName === "Basic Constraint") {
            console.log(extension);
            is_ca = extension.parsedValue.cA;
        }
    });

    return { sansDns, sansIp, is_ca };
}

export const extractCSR = (csrPemString: string) => {
    const arrayBuffer = pemToArrayBuffer(csrPemString);
    const asn1 = fromBER(arrayBuffer);
    const csr = new CertificationRequest({ schema: asn1.result });

    // Extract subject information from CSR
    const subjects = csr.subject.typesAndValues.map(typeAndValue => ({
        type: oidToName(typeAndValue.type),
        value: typeAndValue.value.valueBlock.value
    }));
    const getValue = (type: string) => subjects.find(subject => subject.type === type)?.value;

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
        const extensionAttributes = csr.attributes.filter(attribute => oidToName(attribute.type) === "Extension Request");
        if (extensionAttributes.length > 0) {
            const extensions = new Extensions({ schema: extensionAttributes[0].values[0] });
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
        is_ca
    }
}

export const extractCert = (certPemString: string) => {
    if (certPemString == "" || certPemString == "rejected") { return }

    // Decode PEM to DER
    const binaryDer = pemToArrayBuffer(certPemString);

    // Parse DER encoded certificate
    const asn1 = fromBER(binaryDer);
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
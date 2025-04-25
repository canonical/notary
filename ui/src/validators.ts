// This file contains the validation functions for forms in Notary
// A validator function takes in at least the value to be validated, and returns a 
// validationResult object. The validationResult object contains three properties:
// error, caution, and success. Each of these properties is a string that contains
// the validation message. The error property is used to indicate that the value is
// invalid, the caution property is used to indicate that the value is valid but
// may contain mistakes, and the success property is used to indicate that the value is
// valid.

export type validationResult = {
    error: string
    caution: string
    success: string
}

export function validateCommonName(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateOrganizationName(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length < 1 || value.length > 64) {
        vr.caution = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateOrganizationalUnit(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length < 1 || value.length > 64) {
        vr.caution = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateCountryName(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length !== 2) {
        vr.error = "must be exactly 2 characters"
    }
    if (value !== value.toUpperCase()) {
        vr.error = "must be uppercase letters"
    }
    return vr
}

export function validateStateOrProvinceName(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateLocalityName(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length == 0) {
        return vr
    }
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateNotAfter(value: string): validationResult {
    const vr: validationResult = { error: "", caution: "", success: "" };
    const date = new Date(value);
    const now = new Date();
    if (date < now) {
        vr.caution = "This date is in the past";
    }
    return vr
}
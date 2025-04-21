// This file contains the validation functions for forms in Notary
// A validator function takes in at least the value to be validated, and returns an error string if the value is invalid, or an empty string if the value is valid

import { V } from "vitest/dist/chunks/reporters.d.CqBhtcTq.js";

export type validationResult = {
    error: string
    caution: string
    success: string
}

export function validateCommonName(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateOrganizationName(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateOrganizationalUnit(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateCountryName(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length !== 2) {
        vr.error = "must be exactly 2 characters"
    }
    if (!/^[A-Z]{2}$/.test(value)) {
        vr.error = "must be uppercase letters"
    }
    return vr
}

export function validateStateOrProvinceName(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateLocalityName(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    if (value.length < 1 || value.length > 64) {
        vr.error = "must be between 1 and 64 characters"
    }
    return vr
}

export function validateNotAfter(value: string): validationResult {
    let vr: validationResult = { error: "", caution: "", success: "" };
    const date = new Date(value);
    const now = new Date();
    if (date < now) {
        vr.caution = "This date is in the past";
    }
    return vr
}
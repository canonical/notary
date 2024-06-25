import { expect, test } from 'vitest'
import { Dispatch, SetStateAction } from "react"
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from 'react-query'
import Row from './row'

const csr =
{
    'ID': 1,
    'CSR': `-----BEGIN CERTIFICATE REQUEST-----
MIIC5zCCAc8CAQAwRzEWMBQGA1UEAwwNMTAuMTUyLjE4My41MzEtMCsGA1UELQwk
MzlhY2UxOTUtZGM1YS00MzJiLTgwOTAtYWZlNmFiNGI0OWNmMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjM5Wz+HRtDveRzeDkEDM4ornIaefe8d8nmFi
pUat9qCU3U9798FR460DHjCLGxFxxmoRitzHtaR4ew5H036HlGB20yas/CMDgSUI
69DyAsyPwEJqOWBGO1LL50qXdl5/jOkO2voA9j5UsD1CtWSklyhbNhWMpYqj2ObW
XcaYj9Gx/TwYhw8xsJ/QRWyCrvjjVzH8+4frfDhBVOyywN7sq+I3WwCbyBBcN8uO
yae0b/q5+UJUiqgpeOAh/4Y7qI3YarMj4cm7dwmiCVjedUwh65zVyHtQUfLd8nFW
Kl9775mNBc1yicvKDU3ZB5hZ1MZtpbMBwaA1yMSErs/fh5KaXwIDAQABoFswWQYJ
KoZIhvcNAQkOMUwwSjBIBgNVHREEQTA/hwQKmLc1gjd2YXVsdC1rOHMtMC52YXVs
dC1rOHMtZW5kcG9pbnRzLnZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsMA0GCSqGSIb3
DQEBCwUAA4IBAQCJt8oVDbiuCsik4N5AOJIT7jKsMb+j0mizwjahKMoCHdx+zv0V
FGkhlf0VWPAdEu3gHdJfduX88WwzJ2wBBUK38UuprAyvfaZfaYUgFJQNC6DH1fIa
uHYEhvNJBdFJHaBvW7lrSFi57fTA9IEPrB3m/XN3r2F4eoHnaJJqHZmMwqVHck87
cAQXk3fvTWuikHiCHqqdSdjDYj/8cyiwCrQWpV245VSbOE0WesWoEnSdFXVUfE1+
RSKeTRuuJMcdGqBkDnDI22myj0bjt7q8eqBIjTiLQLnAFnQYpcCrhc8dKU9IJlv1
H9Hay4ZO9LRew3pEtlx2WrExw/gpUcWM8rTI
-----END CERTIFICATE REQUEST-----`,
    'Certificate': `-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIURKr+jf7hj60SyAryIeN++9wDdtkwDQYJKoZIhvcNAQEL
BQAwOTELMAkGA1UEBhMCVVMxKjAoBgNVBAMMIXNlbGYtc2lnbmVkLWNlcnRpZmlj
YXRlcy1vcGVyYXRvcjAeFw0yNDAzMjcxMjQ4MDRaFw0yNTAzMjcxMjQ4MDRaMEcx
FjAUBgNVBAMMDTEwLjE1Mi4xODMuNTMxLTArBgNVBC0MJDM5YWNlMTk1LWRjNWEt
NDMyYi04MDkwLWFmZTZhYjRiNDljZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAIzOVs/h0bQ73kc3g5BAzOKK5yGnn3vHfJ5hYqVGrfaglN1Pe/fBUeOt
Ax4wixsRccZqEYrcx7WkeHsOR9N+h5RgdtMmrPwjA4ElCOvQ8gLMj8BCajlgRjtS
y+dKl3Zef4zpDtr6APY+VLA9QrVkpJcoWzYVjKWKo9jm1l3GmI/Rsf08GIcPMbCf
0EVsgq7441cx/PuH63w4QVTsssDe7KviN1sAm8gQXDfLjsmntG/6uflCVIqoKXjg
If+GO6iN2GqzI+HJu3cJoglY3nVMIeuc1ch7UFHy3fJxVipfe++ZjQXNconLyg1N
2QeYWdTGbaWzAcGgNcjEhK7P34eSml8CAwEAAaOBnTCBmjAhBgNVHSMEGjAYgBYE
FN/vgl9cAapV7hH9lEyM7qYS958aMB0GA1UdDgQWBBRJJDZkHr64VqTC24DPQVld
Ba3iPDAMBgNVHRMBAf8EAjAAMEgGA1UdEQRBMD+CN3ZhdWx0LWs4cy0wLnZhdWx0
LWs4cy1lbmRwb2ludHMudmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBAqYtzUwDQYJ
KoZIhvcNAQELBQADggEBAEH9NTwDiSsoQt/QXkWPMBrB830K0dlwKl5WBNgVxFP+
hSfQ86xN77jNSp2VxOksgzF9J9u/ubAXvSFsou4xdP8MevBXoFJXeqMERq5RW3gc
WyhXkzguv3dwH+n43GJFP6MQ+n9W/nPZCUQ0Iy7ueAvj0HFhGyZzAE2wxNFZdvCs
gCX3nqYpp70oZIFDrhmYwE5ij5KXlHD4/1IOfNUKCDmQDgGPLI1tVtwQLjeRq7Hg
XVelpl/LXTQawmJyvDaVT/Q9P+WqoDiMjrqF6Sy7DzNeeccWVqvqX5TVS6Ky56iS
Mvo/+PAJHkBciR5Xn+Wg2a+7vrZvT6CBoRSOTozlLSM=
-----END CERTIFICATE-----`
}

let actionMenuExpanded = 0
const setActionMenuExpanded = (val: number) => {
    actionMenuExpanded = val
}

const queryClient = new QueryClient()
test('Certificate Requests Table Row', () => {
    render(
        <QueryClientProvider client={queryClient}>
            <Row id={csr.ID} csr={csr.CSR} certificate={csr.Certificate} ActionMenuExpanded={actionMenuExpanded} setActionMenuExpanded={setActionMenuExpanded as Dispatch<SetStateAction<number>>} />
        </QueryClientProvider>
    )
    expect(screen.getByText('10.152.183.53')).toBeDefined() // Common name of CSR
    expect(screen.getByLabelText('certificate-expiry-date').innerHTML).toMatch(/^Thu Mar 27/)
    const openActionsButton = screen.getByLabelText("action-menu-button")
    fireEvent.click(openActionsButton);
    expect(actionMenuExpanded).toBe(1)
    render(
        <QueryClientProvider client={queryClient}>
            <Row id={csr.ID} csr={csr.CSR} certificate="rejected" ActionMenuExpanded={actionMenuExpanded} setActionMenuExpanded={setActionMenuExpanded as Dispatch<SetStateAction<number>>} />

        </QueryClientProvider>
    )
    expect(screen.getByText('rejected')).toBeDefined()
    render(
        <QueryClientProvider client={queryClient}>
            <Row id={csr.ID} csr={csr.CSR} certificate="" ActionMenuExpanded={actionMenuExpanded} setActionMenuExpanded={setActionMenuExpanded as Dispatch<SetStateAction<number>>} />
        </QueryClientProvider>
    )
    expect(screen.getByText('outstanding')).toBeDefined()
})
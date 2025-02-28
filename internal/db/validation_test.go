package db_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/canonical/notary/internal/db"
)

const (
	AppleCSR string = `-----BEGIN CERTIFICATE REQUEST-----
MIICsTCCAZkCAQAwbDELMAkGA1UEBhMCQ0ExFDASBgNVBAgMC05vdmEgU2NvdGlh
MRAwDgYDVQQHDAdIYWxpZmF4MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQxEjAQBgNVBAMMCWFwcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOhDSpNbeFiXMQzQcobExHqYMEGzqpX8N9+AR6/HPZWBybgx1hr3
ejqsKornzpVph/dO9UC7O9aBlG071O9VQGHt3OU3rkZIk2009vYwLuSrAlJtnUne
p7KKn2lZGvh7jVyZE5RkS0X27vlT0soANsmcVq/82VneHrF/nbDcK6DOjQpS5o5l
EiNk2CIpYGUkw3WnQF4pBk8t4bNOl3nfpaAOfnmNuBX3mWyfPnaKMCENMpDqL9FR
V/O5bIPLmyH30OHUEJUkWOmFt9GFi+QfMoM0fR34KmRbDz79hZZb/yVPZZJl7l6i
FWXkNR3gxdEnwCZkTgWk5OqS9dCJOtsDE8ECAwEAAaAAMA0GCSqGSIb3DQEBCwUA
A4IBAQCqBX5WaNv/HjkzAyNXYuCToCb8GjmiMqL54t+1nEI1QTm6axQXivEbQT3x
GIh7uQYC06wHE23K6Znc1/G+o3y6lID07rvhBNal1qoXUiq6CsAqk+DXYdd8MEh5
joerEedFqcW+WTUDcqddfIyDAGPqrM9j6/E+aFYyZjJ/xRuMf1zlWMljRiwj1NI9
NxqjsYYQ3zxfUjv8gxXm0hN8Up1O9saoEF+zbuWNdiUWd6Ih3/3u5VBNSxgVOrDQ
CeXyyzkMx1pWTx0rWa7NSa+DMKVVzv46pck/9kLB4gPL8zqvIOMQsf74N0VcbVfd
9jQR8mPXQYPUERl1ZhNrkzkyA0kd
-----END CERTIFICATE REQUEST-----
`
	BananaCSR string = `-----BEGIN CERTIFICATE REQUEST-----
MIICrjCCAZYCAQAwaTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYD
VQQHDAlOYXJsaWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK+vJMxO1GTty09/E4M/RbTCPABleCuYc/uzj72KWaIvoDaanuJ4NBWM
2aUiepxWdMNTR6oe31gLq4agLYT309tXwCeBLQnOxvBFWONmBG1qo0fQkvT5kSoq
AO29D7hkQ0gVwg7EF3qOd0JgbDm/yvexKpYLVvWMQAngHwZRnd5vHGk6M3P7G4oG
mIj/CL2bF6va7GWODYHb+a7jI1nkcsrk+vapc+doVszcoJ+2ryoK6JndOSGjt9SD
uxulWZHQO32XC0btyub63pom4QxRtRXmb1mjM37XEwXJSsQO1HOnmc6ycqUK53p0
jF8Qbs0m8y/p2NHFGTUfiyNYA3EdkjUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IB
AQA+hq8kS2Y1Y6D8qH97Mnnc6Ojm61Q5YJ4MghaTD+XXbueTCx4DfK7ujYzK3IEF
pH1AnSeJCsQeBdjT7p6nv5GcwqWXWztNKn9zibXiASK/yYKwqvQpjSjSeqGEh+Sa
9C9SHeaPhZrJRj0i3NkqmN8moWasF9onW6MNKBX0B+pvBB+igGPcjCIFIFGUUaky
upMXY9IG3LlWvlt+HTfuMZV+zSOZgD9oyqkh5K9XRKNq/mnNz/1llUCBZRmfeRBY
+sJ4M6MJRztiyX4/Fjb8UHQviH931rkiEGtG826IvWIyiRSnAeE8B/VzL0GlT9Zq
ge6lFRxB1FlDuU4Blef8FnOI
-----END CERTIFICATE REQUEST-----`

	StrawberryCSR string = `-----BEGIN CERTIFICATE REQUEST-----
MIICrzCCAZcCAQAwajELMAkGA1UEBhMCSVQxDzANBgNVBAgMBlBhZG92YTEOMAwG
A1UEBwwFUGFkdWExITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEX
MBUGA1UEAwwOc3RyYXdiZXJyeS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDXXHpy+3LLRCImyEQitM9eUdgYkexLz2PcAf89tTpkpt3L1woJw0bv
+YR80UcR2Pg+7uUVm4XSKFvcdyWg8yADHIDDZkEmKFEbrOLUsWWTQEsCpFt5MU4u
6YnYXV0YflPXmRsJRd90NOen+wlM2ajK1gGTtLPdJ6axz15LdcT2uXXIvWhncjgL
CvVpd/x44AMxD/BPf/d27VO5hEjxR//DtcOmS/jA+Zf1+dyIAWs2LH+ctsaPLOcg
1rBiRrHtGL8wmPwgwK9b+QLiq9Ik+dx1Jl6BvC36LRk2CxTxfZ6e4UdYVhtnjMW2
VEUAVg9LtowvXTexESUv6Mh4uQF6pW5ZAgMBAAGgADANBgkqhkiG9w0BAQsFAAOC
AQEAW40HaxjVSDNKeWJ8StWGfstdvk3dwqjsfLgmnBBZSLcGppYEnnRlJxhMJ9Ks
x2IYw7wJ55kOJ7V+SunKPPoY+7PwNDV9Llxp58vvE8CFnOc3WcL9pA2V5LbTXwtT
R7jID5GZjOv0bn3x1WXuKVW5tkYdT6sW14rfGut1T+r1kYls+JQ5ap+BzfMtThZz
38PCnEMmSo0/KmgUu5/LakPoy3JPaFB0bCgViZSWlxiSR44YZPsVaRL8E7Zt/qjJ
glRL/48q/tORtxv18/Girl6oiQholkADaH3j2gB3t/fCLp8guAVLWB9DzhwrqWwP
GFl9zB5HDoij2l0kHrb44TuonQ==
-----END CERTIFICATE REQUEST-----
`

	AppleCert string = `-----BEGIN CERTIFICATE-----
MIIDpzCCAo+gAwIBAgIIdsqGzsuVM8owDQYJKoZIhvcNAQELBQAwHTELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMB4XDTI0MTIxNjE5NDgwMFoXDTI1MTIxNjE5
NDgwMFowbDELMAkGA1UEBhMCQ0ExFDASBgNVBAgMC05vdmEgU2NvdGlhMRAwDgYD
VQQHDAdIYWxpZmF4MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQx
EjAQBgNVBAMMCWFwcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOhDSpNbeFiXMQzQcobExHqYMEGzqpX8N9+AR6/HPZWBybgx1hr3ejqsKorn
zpVph/dO9UC7O9aBlG071O9VQGHt3OU3rkZIk2009vYwLuSrAlJtnUnep7KKn2lZ
Gvh7jVyZE5RkS0X27vlT0soANsmcVq/82VneHrF/nbDcK6DOjQpS5o5lEiNk2CIp
YGUkw3WnQF4pBk8t4bNOl3nfpaAOfnmNuBX3mWyfPnaKMCENMpDqL9FRV/O5bIPL
myH30OHUEJUkWOmFt9GFi+QfMoM0fR34KmRbDz79hZZb/yVPZZJl7l6iFWXkNR3g
xdEnwCZkTgWk5OqS9dCJOtsDE8ECAwEAAaOBmzCBmDAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBRi8EN3wwvmnmaW85Tg078Ac3CF8zALBgNVHQ8EBAMCA+gwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJYXBwbGUuY29tMBEGCWCGSAGG+EIB
AQQEAwIGQDAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3
DQEBCwUAA4IBAQAK0fbSdEqs8XbNlMy8TUU92dWKUHddy/Di3UkUGtN2Xi533VTx
Xh1HrbNvhjHZ1Groeqow31hSlhj56a0hDVaph01cFmjWs5LLRm3FVS75SayWaza2
4AlfvGrsQbdsczJYJW29FdOROdYG9dX5xsdlYKrC7JQEbjUDUwi/jUjVxNCX6Ush
q2wgYdO0JqUTvcRQS6KYIGm/ODVuL8bf415B4QNY0WZz2Es01XBumyVIvUe4g6HO
RmHWzr19m+Q24fkzCvoZURbgoZghzupfWcz2fMlDoiN23FPzXcQB/aZbJSqVVyOs
MBuKdOtX/6nX6vtOXpi8tUtGhb6Esm73BNhb
-----END CERTIFICATE-----
`

	BananaCert string = `-----BEGIN CERTIFICATE-----
MIIDpTCCAo2gAwIBAgIISZTYS5MMIfcwDQYJKoZIhvcNAQELBQAwHTELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMB4XDTI0MTIxNjE5NDgwMFoXDTI1MTIxNjE5
NDgwMFowaTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYDVQQHDAlO
YXJsaWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDETMBEG
A1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AK+vJMxO1GTty09/E4M/RbTCPABleCuYc/uzj72KWaIvoDaanuJ4NBWM2aUiepxW
dMNTR6oe31gLq4agLYT309tXwCeBLQnOxvBFWONmBG1qo0fQkvT5kSoqAO29D7hk
Q0gVwg7EF3qOd0JgbDm/yvexKpYLVvWMQAngHwZRnd5vHGk6M3P7G4oGmIj/CL2b
F6va7GWODYHb+a7jI1nkcsrk+vapc+doVszcoJ+2ryoK6JndOSGjt9SDuxulWZHQ
O32XC0btyub63pom4QxRtRXmb1mjM37XEwXJSsQO1HOnmc6ycqUK53p0jF8Qbs0m
8y/p2NHFGTUfiyNYA3EdkjUCAwEAAaOBnDCBmTAMBgNVHRMBAf8EAjAAMB0GA1Ud
DgQWBBRIjAr8g+ELbkkSRRAXrdiIiGxmLzALBgNVHQ8EBAMCA+gwEwYDVR0lBAww
CgYIKwYBBQUHAwEwFQYDVR0RBA4wDIIKYmFuYW5hLmNvbTARBglghkgBhvhCAQEE
BAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0B
AQsFAAOCAQEAAeluWNaDD7Ka57bZByaYJcE9QOTN1LbFV5kXjBmnVSk9DPf/Ng3I
2xitN6wzW/jGDSCdjl7dzwwlPW5eeTcEeAjQzhVAMIlD/tO0cU+2zrnISIXkQmPW
HbiLNnfLSAFFLZfDWA3KUwtV2u7pfzRDKLpNGbGax7imW984+H6Mkt3n3eJs0Gx1
PyhQhN9LBXFfQ2mMiWdorMyIZgM4zpgRF5IbTBirAmx7GC9F1GMMikMDl3qmNnlI
LEdK4RD0MkvIerkphELEtCsB0GWuB5tT5cw+RGWZzXvVKOsbhjpKpWoqnMfcDkfP
CDD5QTuBTsstDFsAE9bz8wjbGxHDyrTk0g==
-----END CERTIFICATE-----
`
	UnusedCert string = `-----BEGIN CERTIFICATE-----
MIIEUjCCAjoCFE8lmuBE85/RPw2M17Kzl93O+9IJMA0GCSqGSIb3DQEBCwUAMGEx
CzAJBgNVBAYTAlRSMQ4wDAYDVQQIDAVJem1pcjESMBAGA1UEBwwJTmFybGlkZXJl
MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxCzAJBgNVBAMMAm1l
MB4XDTI0MDYyODA4NDIzN1oXDTI1MDYyODA4NDIzN1owajELMAkGA1UEBhMCSVQx
DzANBgNVBAgMBlBhZG92YTEOMAwGA1UEBwwFUGFkdWExITAfBgNVBAoMGEludGVy
bmV0IFdpZGdpdHMgUHR5IEx0ZDEXMBUGA1UEAwwOc3RyYXdiZXJyeS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXXHpy+3LLRCImyEQitM9eUdgY
kexLz2PcAf89tTpkpt3L1woJw0bv+YR80UcR2Pg+7uUVm4XSKFvcdyWg8yADHIDD
ZkEmKFEbrOLUsWWTQEsCpFt5MU4u6YnYXV0YflPXmRsJRd90NOen+wlM2ajK1gGT
tLPdJ6axz15LdcT2uXXIvWhncjgLCvVpd/x44AMxD/BPf/d27VO5hEjxR//DtcOm
S/jA+Zf1+dyIAWs2LH+ctsaPLOcg1rBiRrHtGL8wmPwgwK9b+QLiq9Ik+dx1Jl6B
vC36LRk2CxTxfZ6e4UdYVhtnjMW2VEUAVg9LtowvXTexESUv6Mh4uQF6pW5ZAgMB
AAEwDQYJKoZIhvcNAQELBQADggIBAIZP5KCkgnoZ8SvnRpQT1rA1d1aneiRdnIKI
WznmGdZAJOWGDVjP0fywdDmpxbK9+6qljzwvAm/cRVEGBJXKHfPvpNtLgO/TCKIG
KOhNVttvgyIKB/LhcN36+qdfZrSUD0XqB2e+y5tzY/WSUy00zHVqohHcBydL//xe
mKiHiOwZ1QwZkjmYv2Lqd1xHaU28B98k7wvQuhxKSB2lvlCKBm5NjiQx+ZyG/NMC
W9zGSBRjz+elrSFJFJiIO5gLVBJXOQz029yBdju+PrGG4i5fLAvJSSyCVgNKAK8S
9x17WmsGBxdAEWiOrYYSUbaJGGlJ+GV5z/2hjGx7SDGV6I4YaHBnD7ZvLQ684uka
K8LNVT06RmvkvisdW9edJzzZzzu+B8GuGCV49CUUWInCIVTfIk/FtViUDOiXL8gM
Wk5OqODXJcGI4oK6N+4zfT25XBOMgON6O6JUF6cJtte5/Pv6EZhZeNjkxOGZMy9b
Dh+wnIt2whBkOv4YmE5/P5h4K4xom+XCz3ec0llP/1ehvY5nCFsDNe7qQ2Zlroi3
dYaWAI3cEWYFs2BkcL6yoC/o2lGUnFGzg+zPU0KTwypAseQurBabmbdNXggqhXWZ
X2iP1fzriAc7Go/uLVH4qezAhR+KisfUrkCw8Jyma8lbkmY0f0OWir6cfWxBfuDf
JUdt8AH0
-----END CERTIFICATE-----
	`

	IntermediateCert string = `-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIIOweg0t+OVlswDQYJKoZIhvcNAQELBQAwHTELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMB4XDTI0MTIxNjE5NDgwMFoXDTI5MTIxNjE5
NDgwMFowHTELMAkGA1UEBhMCVFIxDjAMBgNVBAgTBUl6bWlyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1zqJS0FkKlHbBcL8LXL1zOr5GwCyUZUnxa7a
9LReG0dM1d3Vd43zkvpOOOjWKVBEhnYMhWiv3C/qQhsHoj2CoHKnPIlasDA9Zp5l
Ac0wUGjYVqhL/0rL6bnce66UYD7vTP8VwlEjNSi2zYUEhy9w3Kl3jHgFLFVeJ3FJ
p4IzN6QjjJuwP26ml6NQUCwihDi1+5UzKC/qoPi2X8JBmbUFZ9BExsa6yhwNfzap
xmUAL5BHPNBSM92BAJhw4WMw1ohwwSPW0YxsX57HeBX+ECJOKjiQ1gnTuOfI5x4B
wZ+nhV8f/4drlrYLsvAyPvmIRMXq9NoHQARVq8oRPbj20gFGgwIDAQABo1cwVTAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQcyivqMxDTd8ZsW6h3ZvPUlrNSmDAO
BgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEL
BQADggEBALhFsPxBlNYWK2L8HYj0U4BjSeytwTnFP+tpe+OfYQQCIDd2nzgDcYMX
1XnUpQcXqOQzyHAxATsmt73n1sUbqLH+r9Mnip+NzUg85e4eQuhY/ix25XnK6GGd
2vVQjfU38oHetSTnEiEx0bcpRLBZsxrlFptV+887wP8fssjfn0oaF4eixOlYtqJE
bZwKDJVrZsR1n2KlyMZAnzM/KbWQhRp5IpAy4AgJOaGrnxNFaHpgUc/Ul6xjiOR8
yxX3zL8mk9884X2iDU3ioYstesMPzElJzyPo3zNknVFNit4NE8FmTVrRxF49Kmqw
GJzf/lm+M78dOUrm7eHcRVojsoq9HIs=
-----END CERTIFICATE-----
`

	RootCert string = `-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIICMCretEri14wDQYJKoZIhvcNAQELBQAwHTELMAkGA1UE
BhMCVFIxDjAMBgNVBAgTBUl6bWlyMB4XDTI0MTIxNjE5NDcwMFoXDTM0MTIxNjE5
NDcwMFowHTELMAkGA1UEBhMCVFIxDjAMBgNVBAgTBUl6bWlyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA91rc/P6Q7+QJZJCpaWjts/5E0DFkP7Mcaa4e
C+o7e3OIWQSX+8FUcUvuDe5dsOUUE0h/nL1+KJdTHwIlV++oxWX+MgJkzr7Omk04
zH/u/bbdt3yOvpFSFrO6YHfNArFc2RbRmQwHYKvxOpYt1xsV8l89Ll33ZFDWVq/e
cSz4NxVwPc+1cLbZ/7LV31gH2wcyjiuRT0vV/7LX6CVNj+BVB4AtuwK/00VXe1iv
lFIbFbmUlCoV83qeLUwpz9fiCwMoa9FU/ScOwswyxKFYbxm2+Ekw5+26PPIqUhy+
8kJzpw++tu7R3fEpJdldNcEIuQBAh9doYWQTiQpYVW3b5pbc2QIDAQABo0MwQTAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAeBglghkgBhvhCAQ0EERYP
eGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4IBAQDqsbT1JN/WE6jBx466
SKETTK7Imu2mu3wEMruQRGyfE27QMzritWUGN3YfRYTVBiFYvIyHM04rK+gupsyN
+cxTp0WkgcOY7mD3sNfR8Xq8kNBxbCLchM1qGWSAOeaU0y/ORtmHC5+bc2f7rVKA
wna0CJywEhz/mWSvQw8OA9XHiXBt3E42G/F6KbTrRQ92W4c4pNnse1nfw41HXqf+
PnrGInVyWFuljCSdRtK+HuauQRWFpzLJosBgWzsOPPp5DACpAX4VndJ4DHK/WRcF
wymofbxkMTzCPllpL+g86DZawi2GMTLuzGwZ+m7Pb23ezTzgNYdY70yTbGPltUK4
FeKF
-----END CERTIFICATE-----
`

	WrongPKIssuerCert string = `-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUE8WQeUw8YMVJlt37CjOBXJ+R7wQwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYDVQQHDAlOYXJs
aWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UE
AwwCbWUwHhcNMjQwODIyMDkyMDI2WhcNMzQwODIwMDkyMDI2WjBhMQswCQYDVQQG
EwJUUjEOMAwGA1UECAwFSXptaXIxEjAQBgNVBAcMCU5hcmxpZGVyZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQswCQYDVQQDDAJtZTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAI5KK5H6JN8n3ZF8gp4DRLtIuE16MMZu
H6Br59in71lIE64TMiL6ScqVu7x+etUlvTDcLBX5yYpQ5gZLwB9MyqTRqctZDtP8
82Pa/XIkknFPhcfYN/njINKp2mm1P5zsSm8bznhiCnrfxsYZ13lrJBPjsceRgnD4
Z3207STUO9XIKb1qDUo2tRS1t49g4XiYhEaeATftXladO8AjM99ERXF41MRl8TOm
tRvhl0QrJnEn7CTOhbgN9HYdE9Bu6nOVWLM0zjyeqFJGFlWMTCRYwxYx1/jr6vwl
sF8N+8mkuMpQg13oQdFNpCK9YyoWRoC9zKJbh727VSPzqpyR2I1upg8CAwEAAaNT
MFEwHQYDVR0OBBYEFMi9/T/yZ5n6/PFIketk1fsDpXLgMB8GA1UdIwQYMBaAFMi9
/T/yZ5n6/PFIketk1fsDpXLgMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAB+pIJCiRzaWAht4pBMmbrDaymIhaHeBsAkFmleAZo0cKixAZp4cP2J6
zIN4pEHchsX259wRiAoy0oQ4D1B2fUE+4FYKdIUMQqXh3h8eXaOJAea/OOLHU+9q
nJoQ/4LqsLpwEGB0ZUJN8RO+LML3U1FyY+5Y7tNj5JlpWMtBebAEdhDS91fVdAp+
jALl5X1Wbx/dtBQnubm1YolBVYXnI2zYywa8IgpnguCu9NIp3uqSVf0xcBEnNIny
W5/mfOoXTnuKZKTEvButfrlkLsABQvVepitmZGv+q/f4crCkhms8B23WMRLdteiK
BqHOQR7Y7LSxxC+bAa1QdhgumR3PL8I=
-----END CERTIFICATE-----`
	WrongSubjectIssuerCert string = `-----BEGIN CERTIFICATE-----
MIIFqTCCA5GgAwIBAgIUWJY4vKnl3+kQ487QtMfzLDBTnAowDQYJKoZIhvcNAQEL
BQAwZDELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYDVQQHDAlOYXJs
aWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEOMAwGA1UE
AwwFbm90bWUwHhcNMjQwODIyMDkxOTQ4WhcNMzQwODIwMDkxOTQ4WjBkMQswCQYD
VQQGEwJUUjEOMAwGA1UECAwFSXptaXIxEjAQBgNVBAcMCU5hcmxpZGVyZTEhMB8G
A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ4wDAYDVQQDDAVub3RtZTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJU+5YaFlpn+bWvVri5L6Ekm
bAPuavsI/KXY7ufRmc5qb08o1na9lLJ/7TuMD4K36Idnq20n1JohSlrdymBpNZ8O
3m5fYYtkhx5WADlBZsKnC5aZJIChEb4bYcOFLP+d3PooVsAKBxW0Q6TECviQcK7G
xaxEZw0L7FRhX2c9+CxbvRGP6OGVggXZxwkZik/JJ9aym+fltt9QvlxQVBq/GlFY
ZYC+H8jVZ6RnUjugnWcTm9PAsQ6+EHEevAW+dWaDP+gr9AgKKz1EXbc1mVKAVOLH
jb+Ue7RCvFoar/YxYIszD58dOSB/GuAxn+JAjWbnOu7jeX3XeWlKOagUJF9L9TgM
IUWdiuJG8Uu/kK2MjyRFdT8opnPFAXrK7vSuMBzhRtswAlWc8xoZWeSQF+NpjU+s
wbg8ySYTLfZxVB+s/ftxnGU3RM/RWdbZhb0DAuIBsFAGCbnj+Q61/cK4i58JVjUq
zLk+XOwR55LAyS0Y5pj9jDc5mqvS0z7ot7s2OBM1+o8e3KJgdMSXorYkv3toHMGE
IUmPQZCXJtRCjFNgnoWeLDc+oLiN6BlPx7bS4MDN9tMPCJwF6vnxFzLAzdRqY3D7
uRS3chsx7ClMR9MDsSxplC7tptXgv8UTzh1XZjWGCeZq0Gbe927Hmwy2q8k/BFwn
R4PIVSiE7YAZPb0CPmrfAgMBAAGjUzBRMB0GA1UdDgQWBBRgLXukRHTovOG6g9Z5
eCaeh6SxaTAfBgNVHSMEGDAWgBRgLXukRHTovOG6g9Z5eCaeh6SxaTAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAwNq0z26m13RBvZX/uOR5tIQ6j
l/JpSMhocr6GUTKx1NEmyaO9UEAdwHi7nFGocCbCeMNPBxpaJGkSTxe5HefhDJOI
QcnOo1yY9q5HXsp2SPvXjkZ2Palg1rV/u8BChVvULDDT+JtABJlll+cfggh1pkZv
Z3V7Zh7u7gWbnsSnM0X3zVpxGf/cqZNEoHesAaWJA4yYIH2wr5TwqksXGPFE/g/Z
fhUDeI7OP8kM/A8HnCXdxUok2Zf/wyuoPvrFUaPrcYkZK3omT6H24VdyejuBe2k5
+e0ij3nU8DxKEbKn6XaJFhBzAmP1APi8fLIwO6gig/XUWrfKrqO0ax4Vgl4r88Ht
y4hiHmP9kgWjYqUijLpK5ap5607tfbtZ0QIS54HAPAjE77ZdsEGfkAZPmyCTPg41
Q+YWZJS8HogVTZKY267x7u4lQ68jSVBxpeRHGYzd2HWxWGKVQq8pEa2bob9zby/N
QNRikyGkbp7ep5HgBrZeJJJ5zdaqNzVmXY0JIfhkUypSiCe5X1WgZ9GVCC9wi72D
y6MHDTAyVHrSouCqfh9XD6RDN58d+u9kLEg0WJD55wH4E4z+ZZhEMicCWfT/rn+b
b3dRTVslxdJ0dOApn/6zwfRMXgI7j2yRSkA7F39ekwlPhJy2bGrEDgTlDK33AwPU
wM1PZYERQJNOGMAI5Q==
-----END CERTIFICATE-----`
)

func TestCSRValidationSuccess(t *testing.T) {
	cases := []string{AppleCSR, BananaCSR, StrawberryCSR}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCSR%d", i), func(t *testing.T) {
			if err := db.ValidateCertificateRequest(c); err != nil {
				t.Errorf("Couldn't verify valid CSR: %s", err)
			}
		})
	}
}

func TestCSRValidationFail(t *testing.T) {
	wrongString := "this is a real csr!!!"
	wrongStringErr := "PEM Certificate Request string not found or malformed"
	ValidCSRWithoutWhitespace := strings.ReplaceAll(AppleCSR, "\n", "")
	ValidCSRWithoutWhitespaceErr := "PEM Certificate Request string not found or malformed"
	wrongPemType := strings.ReplaceAll(AppleCSR, "CERTIFICATE REQUEST", "SOME RANDOM PEM TYPE")
	wrongPemTypeErr := "given PEM string not a certificate request"
	InvalidCSR := strings.ReplaceAll(AppleCSR, "s", "p")
	InvalidCSRErr := "asn1: syntax error: data truncated"

	cases := []struct {
		input       string
		expectedErr string
	}{
		{
			input:       wrongString,
			expectedErr: wrongStringErr,
		},
		{
			input:       ValidCSRWithoutWhitespace,
			expectedErr: ValidCSRWithoutWhitespaceErr,
		},
		{
			input:       wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
		{
			input:       InvalidCSR,
			expectedErr: InvalidCSRErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCSR%d", i), func(t *testing.T) {
			err := db.ValidateCertificateRequest(c.input)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\nExpected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestCertValidationSuccess(t *testing.T) {
	cases := []string{
		fmt.Sprintf("%s\n%s", BananaCert, IntermediateCert),
		fmt.Sprintf("%s\n%s\n%s", BananaCert, IntermediateCert, RootCert),
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("ValidCert%d", i), func(t *testing.T) {
			if err := db.ValidateCertificate(c); err != nil {
				t.Errorf("Couldn't verify valid Cert: %s", err)
			}
		})
	}
}

func TestCertValidationFail(t *testing.T) {
	wrongCertString := "this is a real cert!!!"
	wrongCertStringErr := "less than 2 certificate PEM strings were found"
	wrongPemType := strings.ReplaceAll(BananaCert, "CERTIFICATE", "SOME RANDOM PEM TYPE")
	wrongPemTypeErr := "a given PEM string was not a certificate"
	InvalidCert := strings.ReplaceAll(BananaCert, "M", "i")
	InvalidCertErr := "x509: malformed certificate"
	singleCert := BananaCert
	singleCertErr := "less than 2 certificate PEM strings were found"
	issuerCertSubjectDoesNotMatch := fmt.Sprintf("%s\n%s", BananaCert, WrongSubjectIssuerCert)
	issuerCertSubjectDoesNotMatchErr := "invalid certificate chain: certificate 0, certificate 1: subjects do not match"
	issuerCertNotCA := fmt.Sprintf("%s\n%s", BananaCert, UnusedCert)
	issuerCertNotCaErr := "invalid certificate chain: certificate 1 is not a certificate authority"

	cases := []struct {
		inputCert   string
		expectedErr string
	}{
		{
			inputCert:   wrongCertString,
			expectedErr: wrongCertStringErr,
		},
		{
			inputCert:   wrongPemType,
			expectedErr: wrongPemTypeErr,
		},
		{
			inputCert:   InvalidCert,
			expectedErr: InvalidCertErr,
		},
		{
			inputCert:   singleCert,
			expectedErr: singleCertErr,
		},
		{
			inputCert:   issuerCertSubjectDoesNotMatch,
			expectedErr: issuerCertSubjectDoesNotMatchErr,
		},
		{
			inputCert:   issuerCertNotCA,
			expectedErr: issuerCertNotCaErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.ValidateCertificate(c.inputCert)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if !strings.HasPrefix(err.Error(), c.expectedErr) {
				t.Errorf("Expected error not found:\nReceived: %s\n Expected: %s", err, c.expectedErr)
			}
		})
	}
}

func TestCertificateMatchesCSRSuccess(t *testing.T) {
	cases := []struct {
		inputCSR  string
		inputCert string
	}{
		{
			inputCSR:  BananaCSR,
			inputCert: fmt.Sprintf("%s\n%s", BananaCert, IntermediateCert),
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.CertificateMatchesCSR(c.inputCert, c.inputCSR)
			if err != nil {
				t.Errorf("Certificate did not match when it should have")
			}
		})
	}
}

func TestCertificateMatchesCSRFail(t *testing.T) {
	certificateDoesNotMatchErr := "certificate does not match CSR"

	cases := []struct {
		inputCSR    string
		inputCert   string
		expectedErr string
	}{
		{
			inputCSR:    AppleCSR,
			inputCert:   fmt.Sprintf("%s\n%s", BananaCert, IntermediateCert),
			expectedErr: certificateDoesNotMatchErr,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("InvalidCert%d", i), func(t *testing.T) {
			err := db.CertificateMatchesCSR(c.inputCert, c.inputCSR)
			if err == nil {
				t.Errorf("No error received. Expected: %s", c.expectedErr)
				return
			}
			if err.Error() != c.expectedErr {
				t.Errorf("Expected error not found:\nReceived: %s\n Expected: %s", err, c.expectedErr)
			}
		})
	}
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		db.HashPassword("Correct Staple Horse") // nolint:errcheck
	}
}

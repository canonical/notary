package db_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/canonical/notary/internal/db"
	tu "github.com/canonical/notary/internal/testutils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestCertificateRequests(t *testing.T) {
	database := tu.MustPrepareMockDB(t)
	t.Run("List", func(t *testing.T) {
		wantResponse := []db.CertificateRequest{
			{
				CSR_ID:        1,
				CSR:           tu.AppleCSR,
				Status:        "pending",
				CertificateID: 0,
				OwnerID:       1,
			}, {
				CSR_ID:        2,
				CSR:           tu.BananaCSR,
				Status:        "active",
				CertificateID: 3,
				OwnerID:       1,
			}, {
				CSR_ID:  3,
				CSR:     tu.StrawberryCSR,
				Status:  "rejected",
				OwnerID: 2,
			}, {
				CSR_ID:  4,
				CSR:     tu.OrangeCSR,
				Status:  "pending",
				OwnerID: 2,
			}, {
				CSR_ID:        5,
				CSR:           tu.RootCACSR,
				Status:        "active",
				CertificateID: 1,
				OwnerID:       1,
			}, {
				CSR_ID:        6,
				CSR:           tu.IntermediateCACSR,
				Status:        "active",
				CertificateID: 2,
				OwnerID:       1,
			},
		}
		t.Run("ListCertificateRequests", func(t *testing.T) {
			gotResponse, err := database.ListCertificateRequests()
			if err != nil {
				t.Errorf("ListCertificateRequests() = error(%v), want error(nil)", err)
			}
			if !cmp.Equal(gotResponse, wantResponse, cmpopts.SortSlices(func(a, b db.CertificateRequest) bool { return a.CSR_ID < b.CSR_ID })) {
				t.Errorf("ListCertificateRequests() returned unexpected diff (-want+got):\n%v", cmp.Diff(wantResponse, gotResponse))
			}
		})
		wantResponse = []db.CertificateRequest{
			{
				CSR_ID:        1,
				CSR:           tu.AppleCSR,
				Status:        "pending",
				CertificateID: 0,
				OwnerID:       1,
			}, {
				CSR_ID:        2,
				CSR:           tu.BananaCSR,
				Status:        "active",
				CertificateID: 3,
				OwnerID:       1,
			}, {
				CSR_ID:  3,
				CSR:     tu.StrawberryCSR,
				Status:  "rejected",
				OwnerID: 2,
			}, {
				CSR_ID:  4,
				CSR:     tu.OrangeCSR,
				Status:  "pending",
				OwnerID: 2,
			},
		}
		t.Run("ListCertificateRequestsWithoutCAs", func(t *testing.T) {
			gotResponse, err := database.ListCertificateRequestsWithoutCAS()
			if err != nil {
				t.Errorf("ListCertificateRequestsWithoutCAS() = error(%v), want error(nil)", err)
			}
			if !cmp.Equal(gotResponse, wantResponse, cmpopts.SortSlices(func(a, b db.CertificateRequest) bool { return a.CSR_ID < b.CSR_ID })) {
				t.Errorf("ListCertificateRequestsWithoutCAS() returned unexpected diff (-want+got):\n%v", cmp.Diff(wantResponse, gotResponse))
			}
		})
		wantChainResponse := []db.CertificateRequestWithChain{
			{
				CSR_ID:           1,
				CSR:              tu.AppleCSR,
				Status:           "pending",
				CertificateChain: "",
				OwnerID:          1,
			}, {
				CSR_ID:           2,
				CSR:              tu.BananaCSR,
				Status:           "active",
				CertificateChain: tu.BananaCertificate + "\n" + tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
				OwnerID:          1,
			}, {
				CSR_ID:  3,
				CSR:     tu.StrawberryCSR,
				Status:  "rejected",
				OwnerID: 2,
			}, {
				CSR_ID:  4,
				CSR:     tu.OrangeCSR,
				Status:  "pending",
				OwnerID: 2,
			}, {
				CSR_ID:           5,
				CSR:              tu.RootCACSR,
				Status:           "active",
				CertificateChain: tu.RootCACertificate,
				OwnerID:          1,
			}, {
				CSR_ID:           6,
				CSR:              tu.IntermediateCACSR,
				Status:           "active",
				CertificateChain: tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
				OwnerID:          1,
			},
		}
		t.Run("ListCertificateRequestsWithCertificates", func(t *testing.T) {
			gotResponse, err := database.ListCertificateRequestsWithCertificates()
			if err != nil {
				t.Errorf("ListCertificateRequestsWithCertificates() = error(%v), want error(nil)", err)
			}
			if !cmp.Equal(gotResponse, wantChainResponse, cmpopts.SortSlices(func(a, b db.CertificateRequestWithChain) bool { return a.CSR_ID < b.CSR_ID })) {
				t.Errorf("ListCertificateRequestsWithCertificates() returned unexpected diff (-want+got):\n%v", cmp.Diff(wantChainResponse, gotResponse))
			}
		})
		cases := []struct {
			desc string

			filter *db.CSRFilter

			wantResponse []db.CertificateRequestWithChain
			wantPanic    bool
		}{
			{
				desc:   "with no filter",
				filter: nil,
				wantResponse: []db.CertificateRequestWithChain{
					{
						CSR_ID:           1,
						CSR:              tu.AppleCSR,
						Status:           "pending",
						CertificateChain: "",
						OwnerID:          1,
					}, {
						CSR_ID:           2,
						CSR:              tu.BananaCSR,
						Status:           "active",
						CertificateChain: tu.BananaCertificate + "\n" + tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
						OwnerID:          1,
					}, {
						CSR_ID:  3,
						CSR:     tu.StrawberryCSR,
						Status:  "rejected",
						OwnerID: 2,
					}, {
						CSR_ID:  4,
						CSR:     tu.OrangeCSR,
						Status:  "pending",
						OwnerID: 2,
					},
				},
			},
			{
				desc:         "with empty filter",
				filter:       &db.CSRFilter{},
				wantResponse: []db.CertificateRequestWithChain{},
				wantPanic:    true,
			},
			{
				desc:      "with csr_id filter",
				filter:    &db.CSRFilter{ID: &[]int64{1}[0]},
				wantPanic: true,
			},
			{
				desc:      "with csr PEM filter",
				filter:    &db.CSRFilter{PEM: &[]string{tu.AppleCSR}[0]},
				wantPanic: true,
			},
			{
				desc:   "with userID filter",
				filter: &db.CSRFilter{OwnerID: &[]int64{1}[0]},
				wantResponse: []db.CertificateRequestWithChain{
					{
						CSR_ID:           1,
						CSR:              tu.AppleCSR,
						Status:           "pending",
						CertificateChain: "",
						OwnerID:          1,
					}, {
						CSR_ID:           2,
						CSR:              tu.BananaCSR,
						Status:           "active",
						CertificateChain: tu.BananaCertificate + "\n" + tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
						OwnerID:          1,
					},
				},
			},
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("ListCertificateRequestsWithCertificatesWithoutCAS/%s", tc.desc), func(t *testing.T) {
				if tc.wantPanic {
					defer func() {
						r := recover()
						if r == nil {
							t.Errorf("ListCertificateRequestsWithCertificatesWithoutCAS(%v) did not panic, want panic('%v')", tc.filter, tc.wantPanic)
						}
					}()
				}
				gotResponse, err := database.ListCertificateRequestsWithCertificatesWithoutCAS(tc.filter)
				if err != nil {
					t.Errorf("ListCertificateRequestsWithCertificatesWithoutCAS(%v) = error(%v), want error(nil)", tc.filter, err)
				}
				if !cmp.Equal(gotResponse, tc.wantResponse, cmpopts.SortSlices(func(a, b db.CertificateRequestWithChain) bool { return a.CSR_ID < b.CSR_ID })) {
					t.Errorf("ListCertificateRequestsWithCertificatesWithoutCAS(%v) returned unexpected diff (-want+got):\n%v", tc.filter, cmp.Diff(tc.wantResponse, gotResponse))
				}
			})
		}
	})

	t.Run("Get", func(t *testing.T) {
		CSRCases := []struct {
			desc string

			filter *db.CSRFilter

			wantResponse *db.CertificateRequest
			wantPanic    bool
		}{
			{
				desc:      "with no filter",
				filter:    nil,
				wantPanic: true,
			}, {
				desc:   "with csr ID",
				filter: &db.CSRFilter{ID: &[]int64{2}[0]},
				wantResponse: &db.CertificateRequest{
					CSR_ID:        2,
					CSR:           tu.BananaCSR,
					Status:        "active",
					CertificateID: 3,
					OwnerID:       1,
				},
			}, {
				desc:   "with csr PEM",
				filter: &db.CSRFilter{PEM: &[]string{tu.BananaCSR}[0]},
				wantResponse: &db.CertificateRequest{
					CSR_ID:        2,
					CSR:           tu.BananaCSR,
					Status:        "active",
					CertificateID: 3,
					OwnerID:       1,
				},
			}, {
				desc:      "with owner ID",
				filter:    &db.CSRFilter{OwnerID: &[]int64{1}[0]},
				wantPanic: true,
			},
		}
		for _, tc := range CSRCases {
			t.Run(fmt.Sprintf("GetCertificateRequests/%s", tc.desc), func(t *testing.T) {
				if tc.wantPanic {
					defer func() {
						r := recover()
						if r == nil {
							t.Errorf("GetCertificateRequests(%v) did not panic, want panic('%v')", tc.filter, tc.wantPanic)
						}
					}()
				}
				gotResponse, err := database.GetCertificateRequest(tc.filter)
				if err != nil {
					t.Errorf("GetCertificateRequests(%v) = error(%v), want error(nil)", tc.filter, err)
				}
				if !cmp.Equal(gotResponse, tc.wantResponse) {
					t.Errorf("GetCertificateRequests(%v) returned unexpected diff (-want+got):\n%v", tc.filter, cmp.Diff(tc.wantResponse, gotResponse))
				}
			})
		}
		CSRWithChainCases := []struct {
			desc string

			filter *db.CSRFilter

			wantResponse *db.CertificateRequestWithChain
			wantPanic    bool
		}{
			{
				desc:      "with no filter",
				filter:    nil,
				wantPanic: true,
			}, {
				desc:   "with csr ID",
				filter: &db.CSRFilter{ID: &[]int64{2}[0]},
				wantResponse: &db.CertificateRequestWithChain{
					CSR_ID:           2,
					CSR:              tu.BananaCSR,
					Status:           "active",
					CertificateChain: tu.BananaCertificate + "\n" + tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
					OwnerID:          1,
				},
			}, {
				desc:   "with csr PEM",
				filter: &db.CSRFilter{PEM: &[]string{tu.BananaCSR}[0]},
				wantResponse: &db.CertificateRequestWithChain{
					CSR_ID:           2,
					CSR:              tu.BananaCSR,
					Status:           "active",
					CertificateChain: tu.BananaCertificate + "\n" + tu.IntermediateCACertificate + "\n" + tu.RootCACertificate,
					OwnerID:          1,
				},
			}, {
				desc:      "with owner ID",
				filter:    &db.CSRFilter{OwnerID: &[]int64{1}[0]},
				wantPanic: true,
			},
		}
		for _, tc := range CSRWithChainCases {
			t.Run(fmt.Sprintf("GetCertificateRequests/%s", tc.desc), func(t *testing.T) {
				if tc.wantPanic {
					defer func() {
						r := recover()
						if r == nil {
							t.Errorf("GetCertificateRequests(%v) did not panic, want panic('%v')", tc.filter, tc.wantPanic)
						}
					}()
				}
				gotResponse, err := database.GetCertificateRequestAndChain(tc.filter)
				if err != nil {
					t.Errorf("GetCertificateRequests(%v) = error(%v), want error(nil)", tc.filter, err)
				}
				if !cmp.Equal(gotResponse, tc.wantResponse) {
					t.Errorf("GetCertificateRequests(%v) returned unexpected diff (-want+got):\n%v", tc.filter, cmp.Diff(tc.wantResponse, gotResponse))
				}
			})
		}
	})

	t.Run("Create", func(t *testing.T) {
		cases := []struct {
			desc string

			csr     string
			ownerID int64

			wantResponse int64
			wantError    error
		}{
			{
				desc:         "valid CSR",
				csr:          tu.GenerateCSR(),
				ownerID:      1,
				wantResponse: 7,
			}, {
				desc:      "invalid CSR",
				csr:       "",
				ownerID:   1,
				wantError: db.ErrInvalidCertificateRequest,
			}, {
				desc:      "invalid OwnerID",
				csr:       tu.GenerateCSR(),
				ownerID:   123456,
				wantError: db.ErrForeignKey,
			},
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("CreateCertificateRequests/%s", tc.desc), func(t *testing.T) {
				gotResponse, err := database.CreateCertificateRequest(tc.csr, tc.ownerID)
				if tc.wantError != nil && !errors.Is(err, tc.wantError) {
					t.Errorf("CreateCertificateRequests(%v, %v) = error(%v), want error(nil)", tc.csr, tc.ownerID, err)
				}
				if !cmp.Equal(gotResponse, tc.wantResponse) {
					t.Errorf("CreateCertificateRequests(%v, %v) returned unexpected diff (-want+got):\n%v", tc.csr, tc.ownerID, cmp.Diff(tc.wantResponse, gotResponse))
				}
			})
		}
	})

	t.Run("Reject", func(t *testing.T) {

	})

	t.Run("Delete", func(t *testing.T) {

	})
}

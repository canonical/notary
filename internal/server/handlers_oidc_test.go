package server

import (
	"testing"

	"github.com/canonical/notary/internal/backends/authentication"
	"github.com/canonical/notary/internal/db"
)

func TestResolveRoleFromClaims(t *testing.T) {
	mapping := authentication.RoleMapping{
		Claim: "groups",
		Values: map[string]int{
			"notary-admins":   int(db.RoleAdmin),
			"notary-managers": int(db.RoleCertificateManager),
			"notary-viewers":  int(db.RoleReadOnly),
		},
	}

	tests := []struct {
		name    string
		mapping authentication.RoleMapping
		claims  map[string]any
		want    db.RoleID
	}{
		{
			name:    "no mapping configured falls back to read only",
			mapping: authentication.RoleMapping{},
			claims:  map[string]any{"groups": []any{"notary-admins"}},
			want:    db.RoleReadOnly,
		},
		{
			name:    "string claim maps to role",
			mapping: mapping,
			claims:  map[string]any{"groups": "notary-managers"},
			want:    db.RoleCertificateManager,
		},
		{
			name:    "list claim maps to role",
			mapping: mapping,
			claims:  map[string]any{"groups": []any{"unrelated", "notary-managers"}},
			want:    db.RoleCertificateManager,
		},
		{
			name:    "most privileged match wins regardless of order",
			mapping: mapping,
			claims:  map[string]any{"groups": []any{"notary-viewers", "notary-admins"}},
			want:    db.RoleAdmin,
		},
		{
			name:    "unmatched claim value falls back to read only",
			mapping: mapping,
			claims:  map[string]any{"groups": []any{"some-other-group"}},
			want:    db.RoleReadOnly,
		},
		{
			name:    "missing claim falls back to read only",
			mapping: mapping,
			claims:  map[string]any{"email": "user@example.com"},
			want:    db.RoleReadOnly,
		},
		{
			name: "out of range role is ignored",
			mapping: authentication.RoleMapping{
				Claim:  "groups",
				Values: map[string]int{"weird": 42},
			},
			claims: map[string]any{"groups": []any{"weird"}},
			want:   db.RoleReadOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveRoleFromClaims(tt.mapping, tt.claims)
			if got != tt.want {
				t.Fatalf("expected role %d, got %d", tt.want, got)
			}
		})
	}
}

func TestOIDCProvidersLookup(t *testing.T) {
	first := &authentication.OIDCRepository{Name: "corp", Issuer: "https://corp.example.com/"}
	second := &authentication.OIDCRepository{Name: "partner", Issuer: "https://partner.example.com/"}
	providers := authentication.OIDCProviders{first, second}

	if !providers.Enabled() {
		t.Fatal("expected providers to be enabled")
	}

	t.Run("empty name selects the first provider", func(t *testing.T) {
		got, ok := providers.Get("")
		if !ok || got != first {
			t.Fatalf("expected the first provider, got %v (ok=%v)", got, ok)
		}
	})

	t.Run("named lookup", func(t *testing.T) {
		got, ok := providers.Get("partner")
		if !ok || got != second {
			t.Fatalf("expected the partner provider, got %v (ok=%v)", got, ok)
		}
	})

	t.Run("unknown name is rejected", func(t *testing.T) {
		if _, ok := providers.Get("nope"); ok {
			t.Fatal("expected lookup of an unknown provider to fail")
		}
	})

	t.Run("lookup by issuer", func(t *testing.T) {
		got, ok := providers.ByIssuer("https://partner.example.com/")
		if !ok || got != second {
			t.Fatalf("expected the partner provider, got %v (ok=%v)", got, ok)
		}
	})

	t.Run("no providers configured", func(t *testing.T) {
		var none authentication.OIDCProviders
		if none.Enabled() {
			t.Fatal("expected an empty provider list to be disabled")
		}
		if _, ok := none.Get(""); ok {
			t.Fatal("expected lookup against an empty provider list to fail")
		}
	})
}

package cluster

import "fmt"

// RequireProvisionedPKI loads and validates the operator-provisioned cluster
// credentials for a node that is about to bootstrap or join. The private key
// never leaves this node; Notary does not issue or transport certificates.
func RequireProvisionedPKI(stateDir, identity string) (*PKI, error) {
	pki, err := LoadPKI(stateDir)
	if err != nil {
		return nil, err
	}
	if err := pki.MatchesIdentity(identity); err != nil {
		return nil, fmt.Errorf("provisioned cluster certificate: %w", err)
	}
	return pki, nil
}

package authentication

import (
	ofgaClient "github.com/openfga/go-sdk"
	ofgaServer "github.com/openfga/openfga/pkg/server"
)

func setupOpenFGA() {
	ofgaClient.NewConfiguration(ofgaClient.Configuration{})
	ofgaServer.MustNewServerWithOpts()
}

// Have a function that Intializes subsystem. all subsystem initializations should move eventually.
//
// Have a function like checkPermission
//
// Have a standard definition of permissions and roles, to be modified in the future.

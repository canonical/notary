package hashing

import (
	"testing"
)

func TestHashPasswordMatchesCanBeValidated(t *testing.T) {
	password := "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("could not hash password: %v", err)
	}

	err = CompareHashAndPassword(hash, password)
	if err != nil {
		t.Fatalf("password should match hash: %v", err)
	}
}

func TestHashPasswordEmptyPasswordReturnsError(t *testing.T) {
	_, err := HashPassword("")
	if err == nil {
		t.Fatalf("hashing empty password should fail")
	}
}

func TestExternallyGeneratedHashMatchesCanBeValidated(t *testing.T) {
	password := "correct horse battery staple"
	// This hash was generated online: https://argon2.online/
	hash := "$argon2id$v=19$m=16,t=2,p=1$cE5sS1k4eTNkdEhjRENsag$8wrqyGXxX5LBqt1Ixr7NSOW9WgM6ggS9XRrQM1Bt2Mw"

	err := CompareHashAndPassword(hash, password)
	if err != nil {
		t.Fatalf("password: %v should match hash: %v but got error: %v", password, hash, err)
	}
}

func TestInvalidPHCArgon2idStringsReturnDefaultParamsAndError(t *testing.T) {
	testCases := []struct {
		desc string
		input string
	}{
		{
			desc: "Empty string",
			input: "",
		},
		{
			desc: "Random string",
			input: "hjljdh7223%%asduy$$dcfas kjf",
		},
		{
			desc: "Not enough fields",
			input: "$argon2id$v=19$salt$password",
		},
		{
			desc: "Too many fields",
			input: "$argon2id$v=19$m=6,t=2,p=1$salt$password$extra",
		},
		{
			desc: "Wrong hash identifier",
			input: "$argon2i$v=19$m=16,t=2,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Wrong hash version",
			input: "$argon2id$v=42$m=16,t=2,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Badly formatted parameters",
			input: "$argon2id$v=19$m:16,t:2,p:1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Missing memory parameter",
			input: "$argon2id$v=19$t=2,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Missing time parameter",
			input: "$argon2id$v=19$m=16,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Missing parallelism parameter",
			input: "$argon2id$v=19$m=16,t=2$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Memory not uint",
			input: "$argon2id$v=19$m=sixteen,t=2,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Time not uint",
			input: "$argon2id$v=19$m=16,t=two,p=1$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Parallelism not uint",
			input: "$argon2id$v=19$m=16,t=2,p=one$cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Salt not valid base64",
			input: "$argon2id$v=19$m=16,t=2,p=1$%cE5sS1k4eTNkdEhjRENsag$Rd6mkWZZPLjfbXG9Uaia4Q",
		},
		{
			desc: "Hash valid base64",
			input: "$argon2id$v=19$m=16,t=2,p=1$cE5sS1k4eTNkdEhjRENsag$R%d6mkWZZPLjfbXG9Uaia4Q",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			params, _, _, err := parseArgon2IDPHC(tC.input)
			if err == nil {
				t.Errorf("should have failed parsing: %s", tC.input)
			}
			if params != DefaultArgon2IDParameters {
				t.Errorf("expected default parameters, got: %v", params)
			}
		})
	}

}

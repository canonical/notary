package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/canonical/sqlair"
)

// ListEntities retrieves all entities of a given type from the database.
func ListEntities[T any](db *Database, query string) ([]T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, fmt.Errorf("%w: error compiling sql query", ErrInternal)
	}

	var entities []T
	err = db.conn.Query(context.Background(), stmt).GetAll(&entities)
	if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
		return nil, ErrInternal
	}

	return entities, nil
}

// GetOneEntity retrieves a single entity of a given type from the database.
func GetOneEntity[T any](db *Database, query string, params T) (*T, error) {
	stmt, err := sqlair.Prepare(query, *new(T))
	if err != nil {
		return nil, fmt.Errorf("%w: error compiling sql query", ErrInternal)
	}

	var result T
	err = db.conn.Query(context.Background(), stmt, params).Get(&result)
	if err != nil {
		if errors.Is(err, sqlair.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, ErrInternal
	}

	return &result, nil
}

// ParseCertificateChain receives a PEM string chain and returns an x.509.Certificate list.
func ParseCertificateChain(pemChain string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	certChainStr, err := SplitCertificateBundle(pemChain)
	if err != nil {
		return nil, err
	}
	for _, certStr := range certChainStr {
		block, _ := pem.Decode([]byte(certStr))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ParsePrivateKey receives a PEM string and returns a private key.
func ParsePrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// ParseCRL receives a PEM string and returns a certificate revocation list.
func ParseCRL(pemCRL string) (*x509.RevocationList, error) {
	block, _ := pem.Decode([]byte(pemCRL))
	revocationList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	return revocationList, nil
}

// SplitCertificateBundle takes in a valid certificate string and formats it.
// The final list has pure certificate PEM strings with no trailing or leading whitespace
func SplitCertificateBundle(cert string) ([]string, error) {
	var buff bytes.Buffer
	var output []string
	certData := []byte(cert)
	for {
		certBlock, rest := pem.Decode(certData)
		if certBlock == nil {
			break
		}
		err := pem.Encode(&buff, certBlock)
		if err != nil {
			return nil, err
		}
		output = append(output, buff.String())
		buff.Reset()
		certData = rest
	}
	return output, nil
}

// AddCertificateToCRL takes in a certificate chain, CA private key, and CRL,
// adds the first certificate in the chain to the CRL, uses the second certificate in the chain and
// the private key to sign a new CRL and returns this new CRL with the certificate added.
func AddCertificateToCRL(certChainPEM string, caPKPEM string, crlPEM string) (string, error) {
	pk, err := ParsePrivateKey(caPKPEM)
	if err != nil {
		return "", err
	}
	crl, err := ParseCRL(crlPEM)
	if err != nil {
		return "", err
	}
	certificates, err := ParseCertificateChain(certChainPEM)
	if err != nil {
		return "", err
	}
	crl.RevokedCertificateEntries = append(crl.RevokedCertificateEntries, x509.RevocationListEntry{
		SerialNumber:   certificates[0].SerialNumber,
		RevocationTime: time.Now(),
	})
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crl, certificates[1], pk)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})), nil
}

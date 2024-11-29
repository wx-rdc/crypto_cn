package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/wx-rdc/crypto_cn/sm2"
	"github.com/wx-rdc/crypto_cn/x509"
)

func createCertificateRequest(t *testing.T, commonName string, sans []string) (*x509.CertificateRequest, crypto.Signer) {
	dnsNames, ips, emails, _ := SplitSANs(sans)
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		SignatureAlgorithm: x509.SM2WithSM3,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return cr, priv
}

func TestNewCertificate(t *testing.T) {
	cr, priv := createCertificateRequest(t, "commonName", []string{"foo.com", "root@foo.com"})
	crBadSignateure, _ := createCertificateRequest(t, "fail", []string{"foo.com"})
	crBadSignateure.PublicKey = priv.Public()

	customSANsData := CreateTemplateData("commonName", nil)
	customSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: PermanentIdentifierType, Value: "123456"},
		{Type: "1.2.3.4", Value: "utf8:otherName"},
	})
	badCustomSANsData := CreateTemplateData("commonName", nil)
	badCustomSANsData.Set(SANsKey, []SubjectAlternativeName{
		{Type: "1.2.3.4", Value: "int:not-an-int"},
	})

	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}

	type args struct {
		cr   *x509.CertificateRequest
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Certificate
		wantErr bool
	}{
		{"okSimple", args{cr, nil}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			DNSNames:       []string{"foo.com"},
			EmailAddresses: []string{"root@foo.com"},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			Extensions:         newExtensions(cr.Extensions),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
			SignatureAlgorithm: SignatureAlgorithm(x509.UnknownSignatureAlgorithm),
		}, false},
		{"okDefaultTemplate", args{cr, []Option{WithTemplate(DefaultLeafTemplate, CreateTemplateData("commonName", []string{"foo.com"}))}}, &Certificate{
			Subject:  Subject{CommonName: "commonName"},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
		}, false},
		{"okCustomSANs", args{cr, []Option{WithTemplate(DefaultLeafTemplate, customSANsData)}}, &Certificate{
			Subject: Subject{CommonName: "commonName"},
			SANs: []SubjectAlternativeName{
				{Type: PermanentIdentifierType, Value: "123456"},
				{Type: "1.2.3.4", Value: "utf8:otherName"},
			},
			Extensions: []Extension{{
				ID:       ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    []byte{48, 44, 160, 22, 6, 8, 43, 6, 1, 5, 5, 7, 8, 3, 160, 10, 48, 8, 12, 6, 49, 50, 51, 52, 53, 54, 160, 18, 6, 3, 42, 3, 4, 160, 11, 12, 9, 111, 116, 104, 101, 114, 78, 97, 109, 101},
			}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
		}, false},
		{"okExample", args{cr, []Option{WithTemplateFile("./testdata/example.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
			},
		})}}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			SANs:           []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			EmailAddresses: []string{"root@foo.com"},
			URIs:           []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
		}, false},
		{"okFullSimple", args{cr, []Option{WithTemplateFile("./testdata/fullsimple.tpl", TemplateData{})}}, &Certificate{
			Version:               3,
			Subject:               Subject{CommonName: "subjectCommonName"},
			SerialNumber:          SerialNumber{big.NewInt(78187493520)},
			Issuer:                Issuer{CommonName: "issuerCommonName"},
			DNSNames:              []string{"doe.com"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			EmailAddresses:        []string{"jane@doe.com"},
			URIs:                  []*url.URL{{Scheme: "https", Host: "doe.com"}},
			SANs:                  []SubjectAlternativeName{{Type: DNSType, Value: "www.doe.com"}},
			Extensions:            []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("extension")}},
			KeyUsage:              KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage:           ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{[]int{1, 3, 6, 1, 4, 1, 44924, 1, 6}, []int{1, 3, 6, 1, 4, 1, 44924, 1, 7}},
			SubjectKeyID:          []byte("subjectKeyId"),
			AuthorityKeyID:        []byte("authorityKeyId"),
			OCSPServer:            []string{"https://ocsp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/ca.crl"},
			PolicyIdentifiers:     PolicyIdentifiers{[]int{1, 2, 3, 4, 5, 6}},
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			NameConstraints: &NameConstraints{
				Critical:                true,
				PermittedDNSDomains:     []string{"jane.doe.com"},
				ExcludedDNSDomains:      []string{"john.doe.com"},
				PermittedIPRanges:       []*net.IPNet{ipNet("127.0.0.1/32")},
				ExcludedIPRanges:        []*net.IPNet{ipNet("0.0.0.0/0")},
				PermittedEmailAddresses: []string{"jane@doe.com"},
				ExcludedEmailAddresses:  []string{"john@doe.com"},
				PermittedURIDomains:     []string{"https://jane.doe.com"},
				ExcludedURIDomains:      []string{"https://john.doe.com"},
			},
			SignatureAlgorithm: SignatureAlgorithm(x509.SM2WithSM3),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
		},
			false},
		{"okOPCUA", args{cr, []Option{WithTemplateFile("./testdata/opcua.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
			},
		})}}, &Certificate{
			Subject:  Subject{CommonName: ""},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign),
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.SM2,
		}, false},
		{"badSignature", args{crBadSignateure, nil}, nil, true},
		{"failTemplate", args{cr, []Option{WithTemplate(`{{ fail "fatal error }}`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"missingTemplate", args{cr, []Option{WithTemplateFile("./testdata/missing.tpl", CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"badJson", args{cr, []Option{WithTemplate(`"this is not a json object"`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"failCustomSANs", args{cr, []Option{WithTemplate(DefaultLeafTemplate, badCustomSANsData)}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificate(tt.args.cr, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

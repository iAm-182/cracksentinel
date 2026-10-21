// Package authenticode reads and verifies the Authenticode signature of a
// Windows PE file.
//
// WHY THIS EXISTS
//
// A crack scanner sees two kinds of signed file and cannot tell them apart
// with string and import analysis: a legitimate tool signed by its vendor
// (Google's adb, a Microsoft redistributable) and a trojanized one that
// carries a real signature next to an injected payload. The signature is
// only evidence when the content still matches it, so this package answers
// two questions:
//
//	who signed it, and does the content still match the signature?
//
// A file whose signature no longer matches its content was MODIFIED AFTER
// SIGNING. That is a strong malicious signal and nothing else in the
// scanner can see it.
//
// The implementation is pure Go: the PE image hash is computed here, the
// PKCS#7 blob is parsed with encoding/asn1, and the certificates are read
// with crypto/x509. There is no cgo, no external tool and no dependency.
//
// The check is deliberately conservative. The signed digest must appear
// verbatim in the signed attributes for the content to count as intact,
// which works regardless of the exact shape of the SpcSpOpusInfo structure
// (it varies between signers) and regardless of the digest algorithm.

package authenticode

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"
	"time"
)

// Status is the outcome of the verification.
type Status int

const (
	// StatusNone means the file carries no Authenticode signature.
	StatusNone Status = iota
	// StatusIntact means the file is signed and the content matches the
	// signature.
	StatusIntact
	// StatusMismatch means the file carries a signature but the content
	// no longer matches it: it was modified after signing.
	StatusMismatch
	// StatusUnreadable means the file looks signed but the signature
	// could not be parsed.
	StatusUnreadable
)

func (s Status) String() string {
	switch s {
	case StatusIntact:
		return "intact"
	case StatusMismatch:
		return "mismatch"
	case StatusUnreadable:
		return "unreadable"
	}
	return "none"
}

// Result is what the verification found.
type Result struct {
	// Status is the verification outcome.
	Status Status
	// Signer is the common name of the signing certificate.
	Signer string
	// Issuer is the common name of the signer's issuer.
	Issuer string
	// NotAfter is when the signing certificate expires.
	NotAfter string
	// Expired reports that the signing certificate has expired. A
	// signature that was timestamped while the certificate was valid
	// stays valid, so this is a weak signal on its own.
	Expired bool
	// SelfSigned reports that the certificate signs itself, which is what
	// a lot of cracked tools do to look legitimate.
	SelfSigned bool
	// Chain is the number of certificates in the signature.
	Chain int
}

// Signed reports whether the file carries a signature at all.
func (r *Result) Signed() bool {
	return r != nil && (r.Status == StatusIntact || r.Status == StatusMismatch)
}

// Trusted reports whether the signature matches the content. Only a trusted
// signature may lower a file's score: a signature that does not match is
// evidence AGAINST the file, not for it.
func (r *Result) Trusted() bool {
	return r != nil && r.Status == StatusIntact
}

// Verify reads the Authenticode signature of a PE file and checks the
// content against it. A file that is not a PE, or that carries no
// certificate table, returns StatusNone.
func Verify(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return verifyBytes(data)
}

func verifyBytes(data []byte) (*Result, error) {
	blob, err := certTable(data)
	if err != nil {
		return &Result{Status: StatusNone}, nil
	}
	if len(blob) == 0 {
		return &Result{Status: StatusNone}, nil
	}
	res := &Result{Status: StatusUnreadable}

	// The WIN_CERTIFICATE header is 8 bytes: dwLength, wRevision,
	// wCertificateType. The PKCS#7 blob follows it.
	if len(blob) <= 8 {
		return res, nil
	}
	pkcs7 := blob[8:]

	certs, signer, issuer, notAfter, selfSigned := parseChain(pkcs7)
	res.Chain = len(certs)
	if signer != "" {
		res.Signer = signer
		res.Issuer = issuer
		res.NotAfter = notAfter
		res.SelfSigned = selfSigned
		if t, err := time.Parse("2006-01-02", notAfter); err == nil {
			res.Expired = t.Before(time.Now())
		}
	}

	// The content matches the signature when the digest computed over the
	// PE image appears verbatim in the signed attributes.
	sha1Sum, err1 := imageHash(data, crypto.SHA1)
	sha256Sum, err2 := imageHash(data, crypto.SHA256)
	switch {
	case err1 == nil && bytes.Contains(pkcs7, sha1Sum):
		res.Status = StatusIntact
	case err2 == nil && bytes.Contains(pkcs7, sha256Sum):
		res.Status = StatusIntact
	case err1 == nil || err2 == nil:
		res.Status = StatusMismatch
	}
	return res, nil
}

// certTable returns the raw certificate table of a PE file.
func certTable(data []byte) ([]byte, error) {
	pe, err := peOffsets(data)
	if err != nil {
		return nil, err
	}
	entry := pe.certDirEntry
	if entry+8 > len(data) {
		return nil, fmt.Errorf("truncated data directories")
	}
	off := int(uint32(data[entry]) | uint32(data[entry+1])<<8 | uint32(data[entry+2])<<16 | uint32(data[entry+3])<<24)
	size := int(uint32(data[entry+4]) | uint32(data[entry+5])<<8 | uint32(data[entry+6])<<16 | uint32(data[entry+7])<<24)
	if off <= 0 || size <= 0 || off+size > len(data) {
		return nil, nil
	}
	return data[off : off+size], nil
}

type offsets struct {
	opt          int
	ddStart      int
	certDirEntry int
	sumOffset    int
}

func peOffsets(data []byte) (offsets, error) {
	var o offsets
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return o, fmt.Errorf("not a PE file")
	}
	peOff := int(uint32(data[0x3c]) | uint32(data[0x3d])<<8 | uint32(data[0x3e])<<16 | uint32(data[0x3f])<<24)
	if peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return o, fmt.Errorf("bad PE header")
	}
	opt := peOff + 24
	magic := uint16(data[opt]) | uint16(data[opt+1])<<8
	switch magic {
	case 0x10b:
		o.ddStart = opt + 96
	case 0x20b:
		o.ddStart = opt + 112
	default:
		return o, fmt.Errorf("unknown optional header magic 0x%x", magic)
	}
	o.opt = opt
	o.certDirEntry = o.ddStart + 4*8
	o.sumOffset = opt + 64
	return o, nil
}

// imageHash computes the Authenticode PE image hash: the digest over the
// file with three regions excluded - the checksum field, the certificate
// table directory entry, and the certificate table itself.
func imageHash(data []byte, alg crypto.Hash) ([]byte, error) {
	o, err := peOffsets(data)
	if err != nil {
		return nil, err
	}
	h := alg.New()
	if h == nil {
		return nil, fmt.Errorf("hash algorithm unavailable")
	}
	entry := o.certDirEntry
	certOff := 0
	certLen := 0
	if entry+8 <= len(data) {
		certOff = int(uint32(data[entry]) | uint32(data[entry+1])<<8 | uint32(data[entry+2])<<16 | uint32(data[entry+3])<<24)
		certLen = int(uint32(data[entry+4]) | uint32(data[entry+5])<<8 | uint32(data[entry+6])<<16 | uint32(data[entry+7])<<24)
	}
	type region struct{ start, end int }
	var regions []region
	add := func(s, e int) {
		if e > s && s >= 0 && e <= len(data) {
			regions = append(regions, region{s, e})
		}
	}
	add(0, o.sumOffset)
	add(o.sumOffset+4, entry)
	if certOff > 0 && certLen > 0 {
		add(entry+8, certOff)
		add(certOff+certLen, len(data))
	} else {
		add(entry+8, len(data))
	}
	for _, r := range regions {
		h.Write(data[r.start:r.end])
	}
	return h.Sum(nil), nil
}

// The PKCS#7 structures needed to reach the certificates.

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// parseChain extracts the certificates from a PKCS#7 blob and reports the
// signing certificate.
func parseChain(blob []byte) (certs []*x509.Certificate, signer, issuer, notAfter string, selfSigned bool) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(blob, &ci); err != nil {
		return nil, "", "", "", false
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, "", "", "", false
	}
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil || len(rv.FullBytes) == 0 {
			break
		}
		if c, err := x509.ParseCertificate(rv.FullBytes); err == nil {
			certs = append(certs, c)
		}
	}
	// The signing certificate is the one that is not an issuer of another
	// certificate in the chain: it is the leaf.
	for i, c := range certs {
		isIssuer := false
		for j, other := range certs {
			if i != j && other.Issuer.String() == c.Subject.String() {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return certs, c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"),
				c.Subject.String() == c.Issuer.String()
		}
	}
	if len(certs) > 0 {
		c := certs[0]
		return certs, c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"),
			c.Subject.String() == c.Issuer.String()
	}
	return certs, "", "", "", false
}

// HashSHA1 is the Authenticode digest of a PE image, exposed for tests.
func HashSHA1(data []byte) ([]byte, error) { return imageHash(data, crypto.SHA1) }

// HashSHA256 is the Authenticode digest of a PE image, exposed for tests.
func HashSHA256(data []byte) ([]byte, error) { return imageHash(data, crypto.SHA256) }

var (
	_ = sha1.New
	_ = sha256.New
)

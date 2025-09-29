package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

const ctExt = "ssh-ct-proof-v1@n621.de"

func usage(err bool) {
	f := os.Stdout
	if err {
		f = os.Stderr
	}

	fmt.Fprintf(f, `Usage:
  %s checksum
  %s verify CT_CONFIG_PATH BASE64_CERT

Commands:
  checksum   Read cert from stdin, derive equivalent pre-cert and print checksum
  verify     Verify CT proof in cert and print authorized_keys if successful
`, os.Args[0], os.Args[0])

	if err {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func parseCert(ascii string) (*ssh.Certificate, error) {
	ascii = strings.TrimSpace(ascii)
	if ascii == "" {
		return nil, errors.New("empty cert input")
	}
	raw, err := base64.StdEncoding.DecodeString(ascii)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not an ssh certificate")
	}
	return cert, nil
}

func preCertHash(cert *ssh.Certificate) crypto.Hash {
	c2 := *cert

	// roll back adding the CT extension...
	delete(c2.Permissions.Extensions, ctExt)
	// ... and the signature
	c2.Signature = nil
	b := c2.Marshal()

	// remove the length prefix of the now-empty signature field
	body := b[:len(b)-4]

	prefix := []byte(ctExt + "\x00")
	return crypto.HashBytes(append(prefix, body...))
}

func unzlib(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return io.ReadAll(zr)
}

func checkCRL(path string, checksum crypto.Hash) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0

	for sc.Scan() {
		line++

		s := sc.Text()
		if strings.HasPrefix(s, "#") {
			continue
		}

		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		dec, err := hex.DecodeString(s)
		if err != nil {
			return false, fmt.Errorf("line %d: invalid hex: %w", line, err)
		}

		if len(dec) != 32 {
			return false, fmt.Errorf("line %d: want 32 bytes, got %d", line, len(dec))
		}

		if bytes.Equal(dec, checksum[:]) {
			return true, nil
		}
	}

	return false, sc.Err()
}

func cat(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	_, err = io.Copy(os.Stdout, f)
	return err
}

func cmdVerify(args []string) error {
	if len(args) < 2 {
		usage(true)
	}

	ctPath := args[0]
	cert, err := parseCert(args[1])
	if err != nil {
		return err
	}

	// get proof
	ext, ok := cert.Permissions.Extensions[ctExt]
	if !ok {
		return fmt.Errorf("no CT extension in certificate")
	}

	proofRaw, err := unzlib([]byte(ext))
	if err != nil {
		return fmt.Errorf("decompressing proof failed: %w", err)
	}

	var pr proof.SigsumProof
	if err := pr.FromASCII(bytes.NewReader(proofRaw)); err != nil {
		return fmt.Errorf("parsing proof failed: %w", err)
	}

	// load key/policy
	submitKey, err := key.ReadPublicKeysFile(filepath.Join(ctPath, "submit.pub"))
	if err != nil {
		return fmt.Errorf("loading submit key failed: %w", err)
	}

	pol, err := policy.ReadPolicyFile(filepath.Join(ctPath, "policy"))
	if err != nil {
		return fmt.Errorf("loading policy failed: %w", err)
	}

	// calculate expected checksum from cert and check CRL
	msg := preCertHash(cert)
	chk := crypto.HashBytes(msg[:])
	crlMatch, err := checkCRL(filepath.Join(ctPath, "crl"), chk)
	if err != nil {
		return fmt.Errorf("CRL check failed: %w", err)
	}
	if crlMatch {
		return errors.New("checksum present in CRL")
	}

	// check proof
	if err := pr.Verify(&msg, submitKey, pol); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return cat(filepath.Join(ctPath, "authorized_keys"))
}

func cmdChecksum() error {
	s := bufio.NewScanner(os.Stdin)

	for s.Scan() {
		cert, err := parseCert(s.Text())
		if err != nil {
			return fmt.Errorf("parse cert: %w", err)
		}

		hash := preCertHash(cert)
		checksum := crypto.HashBytes(hash[:])
		fmt.Println(hex.EncodeToString(checksum[:]))
	}

	return s.Err()
}

func main() {
	if len(os.Args) < 2 {
		usage(true)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error

	switch cmd {
	case "verify":
		err = cmdVerify(args)
	case "checksum":
		err = cmdChecksum()
	case "help", "-h", "--help":
		usage(false)
	default:
		usage(true)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

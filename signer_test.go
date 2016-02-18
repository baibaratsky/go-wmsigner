package wmsigner

import (
	"crypto/rand"
	"testing"
	"errors"
)

const wmid = "405002833238"
const keyFileName = "test.kwm"
const keyPassword = "FvGqPdAy8reVWw789"

const testString = "TEST"
const testSignature = "642c2f71aafe930bcd238d925833414ccba29f2d408f3b77f1d7100111269865a100c6550258420734e96b4c11153ed597af9a28a066ffece8b50b0c5ffa15fe068f"
const anotherTestString = "Another test..."

func TestSign(t *testing.T) {
	signer, err := New(wmid, keyFileName, keyPassword)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Mock the random generator to get nulls only
	rand.Reader = new(randReaderMock)

	signature, err := signer.Sign(testString)
	if err != nil {
		t.Fatal(err.Error())
	}
	if signature != testSignature {
		t.Errorf("Wrong signature %s", signature)
	}

	sameSignature, err := signer.Sign(testString)
	if err != nil {
		t.Fatal(err.Error())
	}
	if sameSignature != signature {
		t.Errorf("Expected the same signature, got different")
	}

	anotherSignature, err := signer.Sign(anotherTestString)
	if err != nil {
		t.Fatal(err.Error())
	}
	if anotherSignature == signature {
		t.Errorf("Expected a different signature, got the same")
	}
}

func TestSignHalfPasswordCase(t *testing.T) {
	// Double password to make its half to be the right password
	signer, err := New(wmid, keyFileName, keyPassword + keyPassword)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Mock the random generator to get nulls only
	rand.Reader = new(randReaderMock)

	signature, err := signer.Sign(testString)
	if err != nil {
		t.Error(err.Error())
	}
	if signature != testSignature {
		t.Errorf("Wrong signature %s", signature)
	}
}

func TestSignRandReaderError(t *testing.T) {
	signer, err := New(wmid, keyFileName, keyPassword)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Mock the random generator to get nulls only
	rand.Reader = new(randReaderBrokenMock)

	_, err = signer.Sign(testString)

	expectedError(t, err, "Rand reader error")
}

func TestWmidError(t *testing.T) {
	_, err := New("", keyFileName, keyPassword)
	expectedError(t, err, "WMID not provided")
}

func TestKeyFileNotFoundError(t *testing.T) {
	const noSuchFile = "no_such_file"
	_, err := New(wmid, noSuchFile, keyPassword)
	expectedError(t, err, "open " + noSuchFile + ": no such file or directory")
}

func TestKeyFileCorruptedError(t *testing.T) {
	_, err := New(wmid, keyFileName, "")
	expectedError(t, err, "Hash check failed. Key file seems to be corrupted.")
}

func expectedError(t *testing.T, err error, text string) {
	if err == nil {
		t.Fatal("Error expected, none found")
	}
	if err.Error() != text {
		t.Errorf("Error text expected: “%s”, actual: “%s”", text, err.Error())
	}
}

type randReaderMock struct{}

func (reader *randReaderMock) Read(b []byte) (n int, err error) {
	n = len(b)
	for i := 0; i < n; i++ {
		b[i] = 0
	}
	return n, nil
}

type randReaderBrokenMock struct{}

func (reader *randReaderBrokenMock) Read(b []byte) (n int, err error) {
	return 0, errors.New("Rand reader error")
}

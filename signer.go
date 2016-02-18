// WebMoney Signer: a native Go implementation of the WMSigner module
package wmsigner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"os"
)

type word [2]byte

type signer struct {
	power, modulus *big.Int;
}

// Create a signature for the given data
func (this *signer) Sign(data string) (string, error) {
	// Make data hash (16 bytes)
	hash := md4hash([]byte(data))
	base := hash[:]

	// Add 40 random bytes
	randomBytes := make([]byte, 40)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	base = append(base, randomBytes...)

	// Add the length of the base (56 = 16 + 40) as the first 2 bytes
	baseLength := uint8(len(base))
	base = append([]byte{baseLength, 0}, base...)
	baseLength += 2

	// Reverse byte order
	baseReversed := reverseBytes(base)

	// Modular exponentiation
	result := new(big.Int).Exp(
		new(big.Int).SetBytes(baseReversed),
		this.power,
		this.modulus,
	)

	// Reverse byte order by 2 bytes
	reversedResult := reverseBytesAsWords(result.Bytes())

	return hex.EncodeToString(reversedResult), nil
}

func New(wmid, keyFileName, keyPassword string) (signer, error) {
	if wmid == "" {
		return signer{}, errors.New("WMID not provided")
	}

	keyFile, err := os.Open(keyFileName)
	if err != nil {
		return signer{}, err
	}
	defer func() {
		err = keyFile.Close()
	}()

	key, verified := initKey(keyFile, wmid, keyPassword)
	if (!verified) {
		// Try one more time using only the first half of the password
		keyFile.Seek(0, 0)
		halfPassword := keyPassword[:int(math.Ceil(float64(len(keyPassword)) / 2))]
		key, verified = initKey(keyFile, wmid, halfPassword)
		if (!verified) {
			return signer{}, errors.New("Hash check failed. Key file seems to be corrupted.")
		}
	}

	newSigner := signer{}
	newSigner.power, newSigner.modulus = key.Extract()

	return newSigner, err
}

func reverseBytes(data []byte) []byte {
	length := len(data)
	reversed := make([]byte, length)
	for i := length; i > 0; i-- {
		reversed[i - 1] = data[length - i]
	}
	return reversed
}

func reverseWords(data []word) []word {
	length := len(data)
	reversed := make([]word, length)
	for i := length; i > 0; i-- {
		reversed[i - 1] = data[length - i]
	}
	return reversed
}

func reverseBytesAsWords(data []byte) []byte {
	if len(data) % 2 != 0 {
		data = append([]byte{0}, data...)
	}
	words := make([]word, len(data) / 2)
	buffer := bytes.NewBuffer(data)
	binary.Read(buffer, binary.LittleEndian, &words)

	words = reverseWords(words)

	var result []byte

	for _, v := range words {
		result = append(result, v[:]...)
	}

	return result
}
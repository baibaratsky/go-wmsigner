package wmsigner

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/md4"
	"math/big"
	"os"
)

type keyContainer struct {
	Reserved uint16
	SignFlag uint16
	Crc      crc
	Length   uint32
	Buffer   buffer
}
type crc [16]byte
type buffer [140]byte

type keyData struct {
	Reserved    uint32
	PowerBase   uint16
	Power       [66]byte
	ModulusBase uint16
	Modulus     [66]byte
}

func (this *keyContainer) Extract() (*big.Int, *big.Int) {
	var data keyData
	binary.Read(bytes.NewReader(this.Buffer[:]), binary.LittleEndian, &data)

	// Reverse the byte order
	copy(data.Power[:], reverseBytes(data.Power[:]))
	copy(data.Modulus[:], reverseBytes(data.Modulus[:]))

	return new(big.Int).SetBytes(data.Power[:]), new(big.Int).SetBytes(data.Modulus[:])
}

func (this *keyContainer) encrypt(wmid, keyPassword string) {
	hash := md4hash([]byte(wmid + keyPassword))
	this.Buffer = xor(this.Buffer, hash, 6)
}

func (this *keyContainer) verify() bool {
	mockKey := keyContainer{
		Reserved: this.Reserved,
		Length: this.Length,
		Buffer: this.Buffer,
	}

	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.LittleEndian, mockKey)

	crc := md4hash(buffer.Bytes())

	return crc == this.Crc
}

func initKey(keyFile *os.File, wmid, keyPassword string) (key keyContainer, verified bool) {
	binary.Read(keyFile, binary.LittleEndian, &key)

	key.encrypt(wmid, keyPassword)

	verified = key.verify()

	return key, verified
}

func md4hash(data []byte) crc {
	length := len(data)

	hash := md4.New()
	hash.Write(data)

	var result crc
	copy(result[:], hash.Sum(data)[length:])

	return result
}

func xor(subject buffer, modifier crc, shift int) buffer {
	subjectLength := len(subject)
	modifierLength := len(modifier)

	var result buffer
	copy(result[:shift - 1], subject[:shift - 1])

	j := 0
	for i := shift; i < subjectLength; i++ {
		result[i] = subject[i] ^ modifier[j]
		j++
		if j == modifierLength {
			j = 0
		}

	}

	return result
}
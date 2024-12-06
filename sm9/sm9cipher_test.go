package sm9

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCipher(t *testing.T) {
	mk, err := MasterKeyGen(rand.Reader)
	if err != nil {
		t.Errorf("mk gen failed:%s", err)
		return
	}

	var hid byte = 1

	var uid1 = []byte("Alice")
	_, err = UserKeyGen(mk, uid1, hid)
	if err != nil {
		t.Errorf("uk1 gen failed:%s", err)
		return
	}

	var uid2 = []byte("Bob")
	ukBob, err := UserKeyGen(mk, uid2, hid)
	if err != nil {
		t.Errorf("uk2 gen failed:%s", err)
		return
	}

	msg := []byte("message")

	// 加密数据给 Bob
	ciphertext, _ := Encrypt(msg, uid2, &mk.MasterPubKey)

	// Bob 解密数据
	plaintext, _ := Decrypt(ciphertext, uid2, ukBob)

	if !bytes.Equal(msg, plaintext) {
		t.Errorf("decrypt failed, \nwant %s\ngot %s\n", string(msg), string(plaintext))
	}
}

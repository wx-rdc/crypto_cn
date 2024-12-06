package sm9

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/pkg/errors"
	"github.com/wx-rdc/crypto_cn/sm4"
	"github.com/wx-rdc/crypto_cn/sm9/sm9curve"
	"github.com/xianghuzhao/kdfcrypt"
)

var KDFSalt = []byte{137, 14, 177, 175, 197, 56, 31, 254, 10, 223, 157, 232, 91, 149, 124, 75, 34, 90, 160, 85, 193, 47, 144, 90, 253, 139, 90, 135, 101, 233, 182, 250}

const _ENC_HID byte = 0x01

type EncMasterKey struct {
	Msk *big.Int
	EncMasterPubKey
}

type EncMasterPubKey struct {
	Mpk *sm9curve.G1
}
type EncUserKey struct {
	Sk *sm9curve.G2
}

func Encrypt(M, uid2 []byte, mpk *MasterPubKey) (C []byte, err error) {
	var hid byte = _ENC_HID
	//step 1:qb = [H1(IDb || hid, n)]P1 + mpk
	n := sm9curve.Order
	uid2h := append(uid2, hid)
	h := hash(uid2h, n, H1)
	qb := new(sm9curve.G1).ScalarMult(sm9curve.Gen1, h)
	qb.Add(qb, mpk.MpkG1)

	//step 2: random r -> [1, n-1]
regen:
	r, err := randFieldElement(rand.Reader, n)
	if err != nil {
		return nil, errors.Errorf("gen rand num failed:%s", err)
	}

	//step 3: c1 = [r]qb
	C1 := new(sm9curve.G1).ScalarMult(qb, r)
	c1Bytes := C1.Marshal()
	//step 4: g = e(mpk, P2)
	g := sm9curve.Pair(mpk.MpkG1, sm9curve.Gen2)
	//step 5: w = g^r
	w := new(sm9curve.GT).ScalarMult(g, r)
	wBytes := w.Marshal()

	//step 6: kdf get aes-key and encrypt with sm4
	//K1len = aes_key_len = 256 bit
	//K2len = mac_len as you like
	var K1len uint32 = 16
	var K2len uint32 = 16
	kdf, err := kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
	if err != nil {
		return nil, errors.Errorf("create kdf failed:%s", err)
	}
	var kdfKey []byte
	kdfKey = append(kdfKey, c1Bytes...)
	kdfKey = append(kdfKey, wBytes...)
	kdfKey = append(kdfKey, uid2...)
	K, err := kdf.Derive(kdfKey, KDFSalt, K1len+K2len)
	K1 := K[:K1len]
	K2 := K[K1len:]
	if err != nil {
		return nil, errors.Errorf("drive kdf failed:%s", err)
	}
	//check K1 == 0
	var zero_count uint32 = 0
	for kc := range K1 {
		if kc == 0 {
			zero_count++
		}
	}
	if zero_count == K1len {
		goto regen
	}
	//encrypt with sm4
	C2, err := sm4.Sm4Cbc(K1, M, true)
	if err != nil {
		return nil, errors.Errorf("sm4 decrypt failed:%s", err)
	}

	//step 7: C3 = MAC(K2, M)
	hm := hmac.New(sha256.New, K2)
	hm.Write(C2)
	//C3 len is always 32 bytes
	C3 := hm.Sum(nil)
	C = append(c1Bytes, C3...)
	C = append(C, C2...)
	return
}

func Decrypt(C, uid2 []byte, uke *UserKey) (M []byte, err error) {
	//C1 64bytes || C3(hmac) 32 bytes || C2(ciphertext) ?? bytes
	//step 1: get C1 form C
	C1 := new(sm9curve.G1)
	c1Bytes := C[:64]
	_, err = C1.Unmarshal(c1Bytes)
	if err != nil {
		return nil, errors.Errorf("C1 unmarshal failed: %v", err)
	}

	//step 2: w = e(C1, deb)
	w := sm9curve.Pair(C1, uke.SkG2)
	wBytes := w.Marshal()

	//step 3: get key form kdf, decrypt with aes
	var K1len uint32 = 16
	var K2len uint32 = 16
	kdf, err := kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
	if err != nil {
		return nil, errors.Errorf("create kdf failed:%s", err)
	}
	//build a new bytes for kdfKey!!
	var kdfKey []byte
	kdfKey = append(kdfKey, c1Bytes...)
	kdfKey = append(kdfKey, wBytes...)
	kdfKey = append(kdfKey, uid2...)
	K, err := kdf.Derive(kdfKey, KDFSalt, K1len+K2len)
	K1 := K[:K1len]
	//check K1 == 0
	var zero_count uint32 = 0
	for kc := range K1 {
		if kc == 0 {
			zero_count++
		}
	}
	if zero_count == K1len {
		return nil, errors.Errorf("sm4 key error:%s", err)
	}
	//decrypt with sm4
	M, err = sm4.Sm4Cbc(K[:K1len], C[96:], false)
	if err != nil {
		return nil, errors.Errorf("sm4 decrypt failed:%s", err)
	}

	//step 4: u = MAC(K2, C2) verify C3 == u
	hm := hmac.New(sha256.New, K[K1len:])
	hm.Write(C[96:])
	//C3 len is always 32 bytes
	u := hm.Sum(nil)
	if !bytes.Equal(u, C[64:96]) {
		return nil, errors.Errorf("MAC verify failed")
	}
	return
}

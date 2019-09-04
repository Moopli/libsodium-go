package cryptobox

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	generichash "github.com/GoKillers/libsodium-go/cryptogenerichash"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
	"testing"
)

// randReader is a cryptographically secure random number generator
var randReader = rand.Reader

func TestCryptoBoxSeal(t *testing.T) {
	sk, pk, exit := CryptoBoxKeyPair()
	if exit != 0 {
		t.Fatalf("CryptoBoxKeyPair failed: %v", exit)
	}
	testStr := "test string 12345678901234567890123456789012345678901234567890"
	cipherText, exit := CryptoBoxSeal([]byte(testStr), pk)
	if exit != 0 {
		t.Fatalf("CryptoBoxSeal failed: %v", exit)
	}
	plaintext, exit := CryptoBoxSealOpen(cipherText, pk, sk)
	if exit != 0 {
		t.Fatalf("CryptoBoxSealOpen failed: %v", exit)
	}
	if string(plaintext) != testStr {
		t.Fatalf("Bad plaintext: %#v", plaintext)
	}
}

type keyPairEd25519 struct {
	priv *[chacha20poly1305.KeySize + chacha20poly1305.KeySize]byte
	pub  *[chacha20poly1305.KeySize]byte
}

type keyPairCurve25519 struct {
	priv *[chacha20poly1305.KeySize]byte
	pub  *[chacha20poly1305.KeySize]byte
}

func TestBoxVsBox(t *testing.T) {
	var err error

	sendKey := keyPairEd25519{}
	sendKey.pub, sendKey.priv, err = sign.GenerateKey(rand.Reader)
	require.NoError(t, err)

	recKey := keyPairCurve25519{}
	recKey.pub, recKey.priv, err = box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("Test /x/nacl/box.Seal against libsodium crypto_box_easy_open", func(t *testing.T) {

		var plaintext = []byte("Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci " +
			"velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem")

		var nonce [24]byte
		// generate ephemeral asymmetric keys
		epk, esk, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)

		var out = make([]byte, 0)
		copy(out, epk[:])

		// now seal the msg with the ephemeral key, nonce and pubKey (which is recipient's publicKey)
		ciphertext := box.Seal(out, plaintext, &nonce, recKey.pub, esk)

		ciphertext2, rc := CryptoBoxEasy(plaintext, nonce[:], recKey.pub[:], esk[:])
		require.Equal(t, 0, rc)
		t.Logf("box.Seal: %s", base64.URLEncoding.EncodeToString(ciphertext))
		t.Logf("crypto_box_easy: %s", base64.URLEncoding.EncodeToString(ciphertext2))

		require.Equal(t, ciphertext, ciphertext2)

		decode, rc := CryptoBoxOpenEasy(ciphertext, nonce[:], epk[:], recKey.priv[:])
		require.Equal(t, 0, rc)
		require.Equal(t, plaintext, decode)
		t.Log("Payload unchanged through encrypt-decrypt.")
	})

	t.Run("Verify nonce equality", func(t *testing.T) {
		// generate ephemeral asymmetric keys
		epk, _, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		nonceCorrect, err := naclNonce(epk[:], recKey.pub[:])
		require.NoError(t, err)

		nonceTest, err := makeNonce(epk[:], recKey.pub[:])
		require.NoError(t, err)

		t.Log("Successful nonce generation. Testing nonce equality:")
		t.Logf("Test nonce: %s", base64.URLEncoding.EncodeToString(nonceTest))
		t.Logf("Correct nonce: %s", base64.URLEncoding.EncodeToString(nonceCorrect))
		require.Equal(t, nonceCorrect, nonceTest)
	})

	t.Run("Test sodiumBoxSeal -> crypto_box_seal_open", func(t *testing.T) {
		payload := []byte("lorem ipsum doler sit magnet, ada piscine elit, consecutive ada piscine velit")

		ciphertext, err := sodiumBoxSeal(payload, recKey.pub)
		require.NoError(t, err)

		message, rc := CryptoBoxSealOpen(ciphertext, recKey.pub[:], recKey.priv[:])
		require.Equal(t, 0, rc)

		require.Equal(t, payload, message)
		t.Log("Payload unchanged through encrypt-decrypt.")
	})
}

func makeNonce(pub1 []byte, pub2 []byte ) ([]byte, error) {
	var nonce [24]byte
	// generate an equivalent nonce to libsodium's (see link above)
	nonceWriter, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub1[:])
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub2[:])
	if err != nil {
		return nil, err
	}

	nonceOut := nonceWriter.Sum(nil)
	copy(nonce[:], nonceOut)

	//copy(nonce[:], nonceSlice)

	return nonce[:], nil
}

func naclNonce(pub1 []byte, pub2 []byte) ([]byte, error) {

	state, rc := generichash.CryptoGenericHashInit(nil, 24)
	if rc != 0 {
		return nil, errors.New("nonce init failed")
	}
	state, rc = generichash.CryptoGenericHashUpdate(state, pub1)
	if rc != 0 {
		return nil, errors.New("nonce update failed")
	}
	state, rc = generichash.CryptoGenericHashUpdate(state, pub2)
	if rc != 0 {
		return nil, errors.New("nonce update failed")
	}
	state, out, rc := generichash.CryptoGenericHashFinal(state, 24)
	if rc != 0 {
		return nil, errors.New("nonce finalization failed")
	}

	return out, nil
}

func sodiumBoxSeal(msg []byte, pubKey *[chacha20poly1305.KeySize]byte) ([]byte, error) {
	var nonce [24]byte
	// generate ephemeral asymmetric keys
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// generate an equivalent nonce to libsodium's (see link above)
	nonceSlice, err := makeNonce(epk[:], pubKey[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[:], nonceSlice)

	var out = make([]byte, len(epk))
	copy(out, epk[:])

	// now seal the msg with the ephemeral key, nonce and pubKey (which is recipient's publicKey)
	ret := box.Seal(out, msg, &nonce, pubKey, esk)

	return ret, nil
}
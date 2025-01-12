package cryptobox_test

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"github.com/GoKillers/libsodium-go/cryptobox"
	generichash "github.com/GoKillers/libsodium-go/cryptogenerichash"
	"github.com/GoKillers/libsodium-go/cryptosign"
	"github.com/agl/ed25519/extra25519"
	"github.com/btcsuite/btcutil/base58"
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
	sk, pk, exit := cryptobox.CryptoBoxKeyPair()
	if exit != 0 {
		t.Fatalf("CryptoBoxKeyPair failed: %v", exit)
	}
	testStr := "test string 12345678901234567890123456789012345678901234567890"
	cipherText, exit := cryptobox.CryptoBoxSeal([]byte(testStr), pk)
	if exit != 0 {
		t.Fatalf("CryptoBoxSeal failed: %v", exit)
	}
	plaintext, exit := cryptobox.CryptoBoxSealOpen(cipherText, pk, sk)
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

		ciphertext2, rc := cryptobox.CryptoBoxEasy(plaintext, nonce[:], recKey.pub[:], esk[:])
		require.Equal(t, 0, rc)
		t.Logf("box.Seal: %s", base64.URLEncoding.EncodeToString(ciphertext))
		t.Logf("crypto_box_easy: %s", base64.URLEncoding.EncodeToString(ciphertext2))

		require.Equal(t, ciphertext, ciphertext2)

		decode, rc := cryptobox.CryptoBoxOpenEasy(ciphertext, nonce[:], epk[:], recKey.priv[:])
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

		message, rc := cryptobox.CryptoBoxSealOpen(ciphertext, recKey.pub[:], recKey.priv[:])
		require.Equal(t, 0, rc)

		require.Equal(t, payload, message)
		t.Log("Payload unchanged through encrypt-decrypt.")
	})

	t.Run("Test sodiumBoxSeal -> sodiumBoxSealOpen", func(t *testing.T) {
		payload := []byte("lorem ipsum doler sit magnet, ada piscine elit, consecutive ada piscine velit")

		ciphertext, err := sodiumBoxSeal(payload, recKey.pub)
		require.NoError(t, err)

		message, err := sodiumBoxSealOpen(ciphertext, recKey.pub, recKey.priv)
		require.NoError(t, err)

		require.Equal(t, payload, message)
		t.Log("Payload unchanged through encrypt-decrypt.")
	})

	t.Run("Test CryptoBoxSeal -> sodiumBoxSealOpen", func(t *testing.T) {
		payload := []byte("lorem ipsum doler sit magnet, ada piscine elit, consecutive ada piscine velit")

		ciphertext, rc := cryptobox.CryptoBoxSeal(payload, recKey.pub[:])
		require.Equal(t, 0, rc)

		message, err := sodiumBoxSealOpen(ciphertext, recKey.pub, recKey.priv)
		require.NoError(t, err)

		require.Equal(t, payload, message)
		t.Log("Payload unchanged through encrypt-decrypt.")
	})
}

func TestKeyConversion(t *testing.T) {
	var err error

	t.Run("Test secret key conversion from Ed25519 to curve25519", func(t *testing.T) {
		testKey := keyPairEd25519{}
		testKey.pub, testKey.priv, err = sign.GenerateKey(randReader)
		require.NoError(t, err)

		ret, rc := cryptosign.CryptoSignEd25519SkToCurve25519(testKey.priv[:])
		require.Equal(t, 0, rc)

		ret2, err := secretEd25519toCurve25519(testKey.priv)
		require.NoError(t, err)

		print("Expected conversion: ", base64.URLEncoding.EncodeToString(ret), "\n")
		print("Actual conversion  : ", base64.URLEncoding.EncodeToString(ret2[:]), "\n")
		require.ElementsMatch(t, ret, ret2[:])
	})

	t.Run("Test public key conversion from Ed25519 to curve25519", func(t *testing.T) {
		testKey := keyPairEd25519{}
		testKey.pub, testKey.priv, err = sign.GenerateKey(randReader)
		require.NoError(t, err)

		pub1, rc := cryptosign.CryptoSignEd25519PkToCurve25519(testKey.pub[:])
		require.Equal(t, 0, rc)

		pub2, err := publicEd25519toCurve25519(testKey.pub)
		require.NoError(t, err)

		print("Expected conversion: ", base64.URLEncoding.EncodeToString(pub1), "\n")
		print("Actual conversion  : ", base64.URLEncoding.EncodeToString(pub2[:]), "\n")
		require.ElementsMatch(t, pub1, pub2[:])
	})

	t.Run("Test large number of public key conversions", func(t *testing.T) {
		testKey := keyPairEd25519{}

		for i := 0; i < 30000; i++ {
			testKey.pub, testKey.priv, err = sign.GenerateKey(randReader)
			require.NoError(t, err)

			pub1, rc := cryptosign.CryptoSignEd25519PkToCurve25519(testKey.pub[:])
			require.Equal(t, 0, rc)

			pub2, err := publicEd25519toCurve25519(testKey.pub)
			require.NoError(t, err)

			require.ElementsMatch(t, pub1, pub2[:])
		}

	})

	t.Run("Generate public key test data", func(t *testing.T) {

		edKey := keyPairEd25519{}
		keys := []keyPairEd25519{}
		for i := 0; i < 20; i++ {
			edKey.pub, edKey.priv, err = sign.GenerateKey(randReader)
			keys = append(keys, edKey)
			require.NoError(t, err)
			keyString := base58.Encode(edKey.pub[:])
			print("\"", keyString, "\",\n")
		}

		println("")

		for _, key := range keys {
			curvePub, rc := cryptosign.CryptoSignEd25519PkToCurve25519(key.pub[:])
			require.Equal(t, 0, rc)

			keyString := base58.Encode(curvePub[:])
			print("\"", keyString, "\",\n")
		}
	})

	t.Run("Generate private key test data", func(t *testing.T) {

		edKey := keyPairEd25519{}
		keys := []keyPairEd25519{}
		for i := 0; i < 20; i++ {
			edKey.pub, edKey.priv, err = sign.GenerateKey(randReader)
			keys = append(keys, edKey)
			require.NoError(t, err)
			keyString := base58.Encode(edKey.priv[:])
			print("\"", keyString, "\",\n")
		}

		println("")

		for _, key := range keys {
			curvePriv, rc := cryptosign.CryptoSignEd25519SkToCurve25519(key.priv[:])
			require.Equal(t, 0, rc)

			keyString := base58.Encode(curvePriv[:])
			print("\"", keyString, "\",\n")
		}
	})
}

func publicEd25519toCurve25519(pub *[chacha20poly1305.KeySize]byte) (*[chacha20poly1305.KeySize]byte, error) {
	pkOut := new([32]byte)
	success := extra25519.PublicKeyToCurve25519(pkOut, pub)
	if !success {
		return nil, errors.New("Failed to convert public key")
	}
	return pkOut, nil
}


// secretEd25519toCurve25519 converts a secret key from Ed25519 to curve25519 format
// Made with reference to https://github.com/agl/ed25519/blob/master/extra25519/extra25519.go and
// https://github.com/jedisct1/libsodium/blob/927dfe8e2eaa86160d3ba12a7e3258fbc322909c/src/libsodium/crypto_sign/ed25519/ref10/keypair.c#L70
func secretEd25519toCurve25519(priv *[chacha20poly1305.KeySize + chacha20poly1305.KeySize]byte) (*[chacha20poly1305.KeySize]byte, error) {
	hasher := sha512.New()
	_, err := hasher.Write(priv[:32])
	if err != nil {
		return nil, err
	}

	hash := hasher.Sum(nil)

	hash[0] &= 248  // clr lower 3 bits
	hash[31] &= 127 // clr upper 1 bit
	hash[31] |= 64  // set 6th bit

	out := new([chacha20poly1305.KeySize]byte)
	copy(out[:], hash)
	return out, nil
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

func sodiumBoxSealOpen(msg []byte, recPub *[32]byte, recPriv *[32]byte) ([]byte, error) {
	if len(msg) < 32 {
		return nil, errors.New("Message too short")
	}
	var epk [32]byte
	copy(epk[:], msg[:32])

	var nonce [24]byte
	nonceSlice, err := makeNonce(epk[:], recPub[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[:], nonceSlice)


	out, success := box.Open(nil, msg[32:], &nonce, &epk, recPriv)
	if !success {
		return nil, errors.New("Failed to unpack")
	}

	return out, nil
}

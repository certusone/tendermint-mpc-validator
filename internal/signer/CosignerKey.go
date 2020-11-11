package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	tmCrypto "github.com/tendermint/tendermint/crypto"
	tmCryptoEncoding "github.com/tendermint/tendermint/crypto/encoding"
	tmProtoCrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

// CosignerKey is a single key for an m-of-n threshold signer.
type CosignerKey struct {
	PubKey       tmCrypto.PubKey  `json:"pub_key"`
	ShareKey     []byte           `json:"secret_share"`
	RSAKey       rsa.PrivateKey   `json:"rsa_key"`
	ID           int              `json:"id"`
	CosignerKeys []*rsa.PublicKey `json:"rsa_pubs"`
}

func (cosignerKey *CosignerKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerKey

	// marshal our private key and all public keys
	privateBytes := x509.MarshalPKCS1PrivateKey(&cosignerKey.RSAKey)
	rsaPubKeysBytes := make([][]byte, 0)
	for _, pubKey := range cosignerKey.CosignerKeys {
		publicBytes := x509.MarshalPKCS1PublicKey(pubKey)
		rsaPubKeysBytes = append(rsaPubKeysBytes, publicBytes)
	}

	protoPubkey, err := tmCryptoEncoding.PubKeyToProto(cosignerKey.PubKey)
	if err != nil {
		return nil, err
	}

	protoBytes, err := protoPubkey.Marshal()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&struct {
		RSAKey       []byte   `json:"rsa_key"`
		Pubkey       []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Pubkey:       protoBytes,
		RSAKey:       privateBytes,
		CosignerKeys: rsaPubKeysBytes,
		Alias:        (*Alias)(cosignerKey),
	})
}

func (cosignerKey *CosignerKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerKey

	aux := &struct {
		RSAKey       []byte   `json:"rsa_key"`
		Pubkey       []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Alias: (*Alias)(cosignerKey),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(aux.RSAKey)
	if err != nil {
		return err
	}

	var protoPubkey tmProtoCrypto.PublicKey
	err = protoPubkey.Unmarshal(aux.Pubkey)
	if err != nil {
		return err
	}

	pubkey, err := tmCryptoEncoding.PubKeyFromProto(protoPubkey)
	if err != nil {
		return err
	}

	// unmarshal the public key bytes for each cosigner
	cosignerKey.CosignerKeys = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.CosignerKeys {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		cosignerKey.CosignerKeys = append(cosignerKey.CosignerKeys, cosignerRsaPubkey)
	}

	cosignerKey.RSAKey = *privateKey
	cosignerKey.PubKey = pubkey
	return nil
}

// LoadCosignerKey loads a CosignerKey from file.
func LoadCosignerKey(file string) (CosignerKey, error) {
	pvKey := CosignerKey{}
	keyJSONBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return pvKey, err
	}

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return pvKey, err
	}

	return pvKey, nil
}

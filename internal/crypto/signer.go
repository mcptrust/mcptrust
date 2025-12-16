package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	privateKeyType = "ED25519 PRIVATE KEY"
	publicKeyType  = "ED25519 PUBLIC KEY"
)

// GenerateKeys ed25519
func GenerateKeys(privateKeyPath, publicKeyPath string) error {
	// gen keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// save private
	privateBlock := &pem.Block{
		Type:  privateKeyType,
		Bytes: privateKey,
	}
	privateFile, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateFile.Close()

	if err := pem.Encode(privateFile, privateBlock); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// save public
	publicBlock := &pem.Block{
		Type:  publicKeyType,
		Bytes: publicKey,
	}
	publicFile, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicFile.Close()

	if err := pem.Encode(publicFile, publicBlock); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// Sign data
func Sign(data []byte, privateKeyPath string) ([]byte, error) {
	// load key
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != privateKeyType {
		return nil, fmt.Errorf("invalid key type: expected %s, got %s", privateKeyType, block.Type)
	}

	privateKey := ed25519.PrivateKey(block.Bytes)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	// sign
	signature := ed25519.Sign(privateKey, data)
	return signature, nil
}

// Verify
func Verify(data []byte, signature []byte, publicKeyPath string) (bool, error) {
	// load pk
	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != publicKeyType {
		return false, fmt.Errorf("invalid key type: expected %s, got %s", publicKeyType, block.Type)
	}

	publicKey := ed25519.PublicKey(block.Bytes)
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	// check sig
	valid := ed25519.Verify(publicKey, data, signature)
	return valid, nil
}

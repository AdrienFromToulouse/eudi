package main

import (
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// Credential represents a simplified Verifiable Credential (VC)
type Credential struct {
	ID           string                 `json:"id"`
	Type         []string               `json:"type"`
	Issuer       string                 `json:"issuer"`
	IssuanceDate time.Time              `json:"issuanceDate"`
	Subject      map[string]interface{} `json:"credentialSubject"`
	Proof        *groth16.Proof         `json:"proof"`
}

// Proof represents the cryptographic proof for the VC
type Proof struct {
	Type                string    `json:"type"`
	Created             time.Time `json:"created"`
	ProofSignatureValue string    `json:"proofSignatureValue"`
}

// Wallet stores user credentials
type Wallet struct {
	Credentials []Credential
}

func NewWallet() (*Wallet, error) {
	return &Wallet{
		Credentials: []Credential{},
	}, nil
}

// Creates a new VC
func (w *Wallet) IssueCredential(pk groth16.ProvingKey, vk groth16.VerifyingKey, r1cs constraint.ConstraintSystem, subject map[string]interface{}) (Credential, *AgeCheckCircuit, error) {
	// Extract birth year from subject
	birthYearFloat, ok := subject["birthDate"].(string)
	if !ok {
		return Credential{}, nil, fmt.Errorf("birthDate field is missing or not a string")
	}

	// Convert "YYYY-MM-DD" to an integer year
	var birthYear int
	_, err := fmt.Sscanf(birthYearFloat, "%d", &birthYear)
	if err != nil {
		return Credential{}, nil, fmt.Errorf("failed to parse birth year: %v", err)
	}

	// Use the current year dynamically
	currentYear := time.Now().Year()

	// Run the ZKP proof generation
	zkpProof, circuit, err := generateZKProof(pk, r1cs, birthYear, currentYear)
	if err != nil {
		return Credential{}, nil, fmt.Errorf("failed to generate ZKP proof: %v", err)
	}

	cred := Credential{
		ID:           fmt.Sprintf("urn:uuid:%d", time.Now().UnixNano()),
		Type:         []string{"VerifiableCredential", "eIDASIdentityCredential"},
		Issuer:       "did:example:issuer123",
		IssuanceDate: time.Now(),
		Subject:      subject,
		Proof:        zkpProof,
	}

	w.Credentials = append(w.Credentials, cred)

	return cred, circuit, nil
}

func VerifyCredential(circuit *AgeCheckCircuit, cred *Credential, vk groth16.VerifyingKey) (bool, error) {
	err := verifyZKProof(circuit, cred.Proof, vk)
	if err != nil {
		return false, err
	}
	return true, err
}

// HTTP Handlers
func issueCredential(pk groth16.ProvingKey, vk groth16.VerifyingKey, r1cs constraint.ConstraintSystem, w *Wallet) (*Credential, *AgeCheckCircuit) {
	subject := map[string]interface{}{
		"id":          "did:example:user123",
		"givenName":   "Adrien",
		"familyName":  "Smith",
		"birthDate":   "1984-01-01",
		"nationality": "FR",
	}

	cred, circuit, err := w.IssueCredential(pk, vk, r1cs, subject)
	if err != nil {
		fmt.Printf("Failed to issue credential: %v\n", err)
		return nil, nil
	}
	fmt.Printf("Cred: %v\n", cred)

	return &cred, circuit
}

func verifyCredential(c *Credential, circuit *AgeCheckCircuit, vk groth16.VerifyingKey) {
	valid, err := VerifyCredential(circuit, c, vk)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}

	if valid {
		fmt.Println("Credential is valid.")
	} else {
		fmt.Println("Credential is not valid.")
	}
}

func main() {
	wallet, err := NewWallet()
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, r1cs, err := InitCircuit()
	if err != nil {
		log.Fatal(err)
	}

	cred, circuit := issueCredential(pk, vk, r1cs, wallet)
	verifyCredential(cred, circuit, vk)
}

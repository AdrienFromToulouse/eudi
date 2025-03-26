package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Inspired by https://arriqaaq.substack.com/p/unlocking-the-power-of-zero-knowledge

// AgeCheckCircuit defines the relationship between inputs (BirthYear, CurrentYear) and the condition (age > 18).
type AgeCheckCircuit struct {
	BirthYear   frontend.Variable `gnark:"birthYear,secret"`   // private input
	CurrentYear frontend.Variable `gnark:"currentYear,public"` // public input
}

// Define declares the circuit constraints
func (circuit *AgeCheckCircuit) Define(api frontend.API) error {
	// Calculate age
	age := api.Sub(circuit.CurrentYear, circuit.BirthYear)

	// Prove that age > 18 without revealing exact age
	isOver18 := api.Cmp(age, 18)
	api.AssertIsEqual(isOver18, 1)

	return nil
}

func InitCircuit() (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem, error) {
	var circuit AgeCheckCircuit

	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Printf("Failed to compile circuit: %v\n", err)
		return nil, nil, nil, err
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Failed to setup: %v\n", err)
		return nil, nil, nil, err
	}

	return pk, vk, r1cs, err
}

func generateZKProof(pk groth16.ProvingKey, r1cs constraint.ConstraintSystem, birthYear, currentYear int) (*groth16.Proof, *AgeCheckCircuit, error) {
	assignment := &AgeCheckCircuit{
		BirthYear:   birthYear,   // secret value (kept private)
		CurrentYear: currentYear, // public value
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness: %v\n", err)
		return nil, nil, err
	}

	// Generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Failed to generate proof: %v\n", err)
		return nil, nil, err
	}

	return &proof, assignment, nil
}

func verifyZKProof(circuit *AgeCheckCircuit, proof *groth16.Proof, vk groth16.VerifyingKey) error {
	witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness: %v\n", err)
		return err
	}

	// Verify the proof
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("Failed to get public witness: %v\n", err)
		return err
	}

	err = groth16.Verify(*proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("Proof verification failed: %v\n", err)
		return err
	}

	return nil
}

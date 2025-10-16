# Double-Hashing in verifySignature() causes Denail of service

## Brief/Intro
A high-severity bug exists in the signature verification logic in `verifySignature( )` inside `ledger.go` that causes all Ledger-based EIP-712 signature verifications to fail. This issue effectively causes a Denial of Service (DoS) for all Ledger hardware wallet users interacting through this code path.

## Vulnerability Details
The vulnerability stems from an accidental double-hashing of the `data ` parameter used in verifying the recovered public key in `verifySignature()`.

```go
func verifySignature(account ledger.Account, data, sig []byte) error {
	if len(sig) != crypto.SignatureLength {
		return fmt.Errorf("invalid signature length: %d", len(sig))
	}
	// Copy signature as it would otherwise be modified
	sigCopy := append(make([]byte, 0, len(sig)), sig...)
	// Subtract 27 to match ECDSA standard
	sigCopy[crypto.RecoveryIDOffset] -= 27
	derivedPubkey, err := crypto.Ecrecover(crypto.Keccak256(data), sigCopy)
	if err != nil {
		return err
	}
	if !bytes.Equal(derivedPubkey, crypto.FromECDSAPub(account.PubKey)) {
		return errors.New("unauthorized: invalid signature verification")
	}
	return nil
}
```
The variable `data` represents the final 32-byte EIP-712 hash,a keccak256 of the structured message returned from `typeddata.ComputeTypedDataAndHash(typedData)`.
```go
func ComputeTypedDataAndHash(typedData TypedData) (hash, data []byte, err error) {
	return crypto.Keccak256(rawData), rawData, nil
}
```
In the calling function `SignSECP256K1`, the `data` variable is populated by `typeddata.ComputeTypedDataAndHash(typedData)`. This function returns the final, 32-byte Keccak256 hash of the EIP-712 structured data. This is the exact hash that the Ledger device signs.
However, inside `verifySignature`, the code performs `crypto.Keccak256(data)` before passing it to `crypto.Ecrecover`. This results in Ecrecover trying to recover the public key based on `keccak256(keccak256(EIP712_message))`, while the signature was created against `keccak256(EIP712_message)`. This consequently fails with "unauthorized: ..." error for every signature verification

```go
if !bytes.Equal(derivedPubkey, crypto.FromECDSAPub(account.PubKey)) {
		return errors.New("unauthorized: invalid signature verification")
	}
```


## Impact Details
Any user who uses a Ledger hardware wallet with this code path will be unable to sign EIP-712 transactions or messages, preventing them from sending transactions, staking, voting, or performing other actions that require Ledger signatures.This is a high-severity Denial of service bug to hadware wallet users.

## References
https://github.com/InjectiveFoundation/injective-core/blob/f1e149e3cc0d5d09d40bd1a382d1e7f9b783da19/injective-chain/crypto/keyring/ledger.go#L120

https://github.com/InjectiveFoundation/injective-core/blob/f1e149e3cc0d5d09d40bd1a382d1e7f9b783da19/injective-chain/crypto/keyring/ledger.go#L160


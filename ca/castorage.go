package ca

import "math/big"

// CA protection (password or key) during new CA
// CA name given during new CA
type CAStorage interface {
	GetCA() (*CA, error)
	StoreCA(ca *CA) error
	GetNextSerialNumber() (*big.Int, error)
}

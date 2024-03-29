package DecentralizedABE

import "github.com/Nik-U/pbc"

type Cipher struct {
	C00        	*pbc.Element   `field:"2"`
	C01			*pbc.Element   `field:"2"`
	C1s         []*pbc.Element `field:"0"`
	C2s         []*pbc.Element `field:"0"`
	C3s         []*pbc.Element `field:"0"`
	C4s         []*pbc.Element `field:"0"`
	CipherText1 []byte
	CipherText2 []byte
	Policy      *Policy
	S			*pbc.Element
}

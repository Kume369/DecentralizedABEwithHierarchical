package DecentralizedABE

import "github.com/Nik-U/PBC"

type Cipher struct {
	C00        	*PBC.Element   `field:"2"`
	C01			*PBC.Element   `field:"2"`
	C1s         []*PBC.Element `field:"0"`
	C2s         []*PBC.Element `field:"0"`
	C3s         []*PBC.Element `field:"0"`
	C4s         []*PBC.Element `field:"0"`
	CipherText1 []byte
	CipherText2 []byte
	Policy      *Policy
	S			*PBC.Element
}

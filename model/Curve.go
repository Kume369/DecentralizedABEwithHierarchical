package DecentralizedABE

import (
	"github.com/Nik-U/pbc"
	"hash"
	// "math/big"
	"fmt"
)

type CurveParam struct {
	Param   *pbc.Params
	Pairing *pbc.Pairing
}

func (this *CurveParam) Initialize() {
	this.Param = pbc.GenerateA(160, 512)
	this.Pairing = this.Param.NewPairing()
}

func (this *CurveParam) GetPairing() *pbc.Pairing {
	return this.Pairing
}

func (this *CurveParam) GetNewG1() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(0).Rand()
	return g
}

func (this *CurveParam) GetNewGT() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(2).Rand()
	return g
}

func (this *CurveParam) GetNewZn() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(3).Rand()
	return g
}

func (this *CurveParam) GetG1FromStringHash(s string, hash hash.Hash) *pbc.Element {
	g := this.Pairing.NewUncheckedElement(0).SetFromStringHash(s, hash)
	return g
}

func (this *CurveParam) GetZnFromStringHash(s string, hash hash.Hash) *pbc.Element {
	g := this.Pairing.NewUncheckedElement(3).SetFromStringHash(s, hash)
	return g
}

func (this *CurveParam) Get0FromG1() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(0).Set0()
	return g
}

func (this *CurveParam) Get0FromGT() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(2).Set0()
	return g
}

func (this *CurveParam) Get0FromZn() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(3).Set0()
	return g
}

func (this *CurveParam) Get1FromG1() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(0).Set1()
	return g
}

func (this *CurveParam) Get1FromGT() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(2).Set1()
	return g
}

func (this *CurveParam) Get1FromZn() *pbc.Element {
	g := this.Pairing.NewUncheckedElement(3).Set1()
	return g
}
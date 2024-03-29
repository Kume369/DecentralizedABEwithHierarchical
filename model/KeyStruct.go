package DecentralizedABE

import (
	"github.com/Nik-U/PBC"
)


type APK struct {
	Galpha *PBC.Element   `field:"0"`
	Gbeta  *PBC.Element	  `field:"0"`			
	Ggamma *PBC.Element   `field:"0"`

}

func (p *APK) Initialize(Galpha *PBC.Element, Gbeta *PBC.Element, Ggamma *PBC.Element) {
	p.Galpha = Galpha
	p.Gbeta = Gbeta
	p.Ggamma = Ggamma
}

func (p *APK) GetGalpha() *PBC.Element {
	return p.Galpha.NewFieldElement().Set(p.Galpha)
}

func (p *APK) GetGbeta() *PBC.Element {
	return p.Gbeta.NewFieldElement().Set(p.Gbeta)
}

func (p *APK) GetGgamma() *PBC.Element {
	return p.Ggamma.NewFieldElement().Set(p.Ggamma)
}

type ASK struct {
	Alpha *PBC.Element `field:"3"`
	Beta  *PBC.Element `field:"3"`
	Gamma *PBC.Element `field:"3"`
}

func (s *ASK) Initialize(alpha *PBC.Element, beta *PBC.Element, gamma *PBC.Element) {
	s.Alpha = alpha
	s.Beta = beta
	s.Gamma = gamma
}

func (s *ASK) GetAlpha() *PBC.Element {
	return s.Alpha.NewFieldElement().Set(s.Alpha)
}

func (s *ASK) GetBeta() *PBC.Element {
	return s.Beta.NewFieldElement().Set(s.Beta)
}

func (s *ASK) GetGamma() *PBC.Element {
	return s.Gamma.NewFieldElement().Set(s.Gamma)
}

type USK struct{
	SK0 string
	SK1 *PBC.Element `field:"0"`
	SK2 *PBC.Element `field:"0"`
}

type TK struct{
	TK0 string
	TK1 *PBC.Element `field:"0"`
	TK2 *PBC.Element `field:"0"`
	TK3 *PBC.Element `field:"0"`
	TK4 *PBC.Element `field:"0"`
}

type VC struct {
	Delta *PBC.Element `field:"0"`
	R 	  *PBC.Element `field:"3"`
}
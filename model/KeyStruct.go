package DecentralizedABE

import (
	"github.com/Nik-U/pbc"
)


type APK struct {
	Galpha *pbc.Element   `field:"0"`
	Gbeta  *pbc.Element	  `field:"0"`			
	Ggamma *pbc.Element   `field:"0"`

}

func (p *APK) Initialize(Galpha *pbc.Element, Gbeta *pbc.Element, Ggamma *pbc.Element) {
	p.Galpha = Galpha
	p.Gbeta = Gbeta
	p.Ggamma = Ggamma
}

func (p *APK) GetGalpha() *pbc.Element {
	return p.Galpha.NewFieldElement().Set(p.Galpha)
}

func (p *APK) GetGbeta() *pbc.Element {
	return p.Gbeta.NewFieldElement().Set(p.Gbeta)
}

func (p *APK) GetGgamma() *pbc.Element {
	return p.Ggamma.NewFieldElement().Set(p.Ggamma)
}

type ASK struct {
	Alpha *pbc.Element `field:"3"`
	Beta  *pbc.Element `field:"3"`
	Gamma *pbc.Element `field:"3"`
}

func (s *ASK) Initialize(alpha *pbc.Element, beta *pbc.Element, gamma *pbc.Element) {
	s.Alpha = alpha
	s.Beta = beta
	s.Gamma = gamma
}

func (s *ASK) GetAlpha() *pbc.Element {
	return s.Alpha.NewFieldElement().Set(s.Alpha)
}

func (s *ASK) GetBeta() *pbc.Element {
	return s.Beta.NewFieldElement().Set(s.Beta)
}

func (s *ASK) GetGamma() *pbc.Element {
	return s.Gamma.NewFieldElement().Set(s.Gamma)
}

type USK struct{
	SK0 string
	SK1 *pbc.Element `field:"0"`
	SK2 *pbc.Element `field:"0"`
}

type TK struct{
	TK0 string
	TK1 *pbc.Element `field:"0"`
	TK2 *pbc.Element `field:"0"`
	TK3 *pbc.Element `field:"0"`
	TK4 *pbc.Element `field:"0"`
}

type VC struct {
	Delta *pbc.Element `field:"0"`
	R 	  *pbc.Element `field:"3"`
}
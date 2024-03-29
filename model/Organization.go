package DecentralizedABE

import (
	"fmt"
	"crypto/sha256"
	"github.com/Nik-U/PBC"
)

type Authority struct {
	ApkMap       map[string]*APK 			
	AskMap		 map[string]*ASK 			
	Name         string						
	Nounce		 *PBC.Element	`field:"3"`

}


func (AA *Authority) GetAPKMap() map[string]*APK {
	return AA.ApkMap
}

func (AA *Authority) GetASKMap() map[string]*ASK {
	return AA.AskMap
}


func (AA *Authority) GenerateNewAttr(attr string, d *DABE) (*APK, error) {
	if AA.ApkMap[attr] != nil || AA.AskMap[attr] != nil {
		return nil, fmt.Errorf("AA already has this attr:%s", attr)
	}

	alpha := d.CurveParam.GetNewZn()
	beta := d.CurveParam.GetNewZn()
	gamma := d.CurveParam.GetNewZn()
	sk := ASK{alpha,beta,gamma}
	Galpha := d.G.NewFieldElement().PowZn(d.G, alpha)
	Gbeta := d.G.NewFieldElement().PowZn(d.G, beta)
	Ggamma := d.G.NewFieldElement().PowZn(d.G, gamma)
	pk := APK{Galpha,Gbeta,Ggamma}
	AA.ApkMap[attr] = &pk
	AA.AskMap[attr] = &sk
	return &pk, nil
}

func (AA *Authority) Authenticate(attr string, GID string, d *DABE) (*VC, error) {
	m := d.CurveParam.GetZnFromStringHash(attr + GID + AA.Nounce.String(), sha256.New())
	r := d.CurveParam.GetNewZn()
	ASK := AA.AskMap[attr]
	alpha := ASK.Alpha
	beta := ASK.Beta
	tmp := r.NewFieldElement().Mul(beta, r)
	x := m.NewFieldElement().Add(alpha, m).ThenAdd(tmp)
	invert := x.NewFieldElement().Invert(x)
	delta := d.G.NewFieldElement().PowZn(d.G, invert)

	vc := VC{delta, r}
	return &vc, nil
}


func (AA *Authority) VerifyandKeyGen(vc *VC, attr string, GID string, d *DABE) (*USK, error) {
	if AA.AskMap[attr] == nil {
		return nil, fmt.Errorf("AA don't have this attr, error when %s", attr)
	}

	ASK := AA.AskMap[attr]

	alpha := ASK.Alpha
	beta := ASK.Beta
	gamma := ASK.Gamma

	invertGamma := gamma.NewFieldElement().Invert(gamma)
	uid := d.CurveParam.GetZnFromStringHash(GID,sha256.New()) 
	HGID := d.CurveParam.GetG1FromStringHash(GID,sha256.New())
	tmp := gamma.NewFieldElement().Mul(gamma, uid)
	invertUid := tmp.NewFieldElement().Invert(tmp)

	key1 := HGID.NewFieldElement().PowZn(HGID, beta).ThenPowZn(invertGamma)


	key2 := d.G.NewFieldElement().PowZn(d.G, alpha).ThenPowZn(invertUid)


	r := d.CurveParam.GetNewZn()
	key3 := d.CurveParam.GetG1FromStringHash(attr,sha256.New())
	key3 = key3.NewFieldElement().PowZn(key3,r)

	sk1 := key1.ThenMul(key2).ThenMul(key3)


	sk2 := d.G.NewFieldElement().PowZn(d.G,tmp)
	sk2 = sk2.NewFieldElement().PowZn(sk2,r)


	return &USK{
		SK0: GID,
		SK1: sk1,
		SK2: sk2,
	},nil
}
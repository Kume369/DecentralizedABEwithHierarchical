package DecentralizedABE

import (
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/PBC"
	"DecentralizedABE/model/AES"
)

type DABE struct {
	CurveParam *CurveParam
	G          *PBC.Element 
	EGG        *PBC.Element 
}


func (d *DABE) GlobalSetup() {
	fmt.Println("DABE GlobalSetup start")
	d.CurveParam = new(CurveParam)
	d.CurveParam.Initialize()
	d.G = d.CurveParam.GetNewG1()
	d.EGG = d.CurveParam.GetNewGT().Pair(d.G, d.G)
	fmt.Println("DABE GlobalSetup success")
}

func (d *DABE) AuthoritySetup(name string) *Authority {
	fmt.Println("DABE AuthoritySetup start")
	nounce := d.CurveParam.GetNewZn()
	return &Authority{
		ApkMap:   make(map[string]*APK),
		AskMap:   make(map[string]*ASK),
		Name:     name,
		Nounce:	  nounce,
	}
}

func (d *DABE) TransKey(privateKeys map[string]*USK, GID string, n *PBC.Element) (map[string]*TK, error) {

	tkMap := make(map[string]*TK)
	for attr, usk := range privateKeys {
		sk0 := usk.SK0
		sk1 := usk.SK1
		sk2 := usk.SK2

		uid := d.CurveParam.GetZnFromStringHash(GID,sha256.New()) 
		HGID := d.CurveParam.GetG1FromStringHash(GID,sha256.New())
		invertN := n.NewFieldElement().Invert(n)

		tk1 := sk1.NewFieldElement().PowZn(sk1, invertN)
		tk2 := sk2.NewFieldElement().PowZn(sk2, invertN)
		tk3 := d.G.NewFieldElement().PowZn(d.G, invertN)
		tk4 := HGID.NewFieldElement().PowZn(HGID, uid).ThenPowZn(invertN)

		tk := &TK{
			TK0:        sk0,
			TK1:        tk1,
			TK2:        tk2,
			TK3:        tk3,
			TK4:        tk4,
		}

		tkMap[attr] = tk
	}

	return tkMap, nil
}

func (d *DABE) OutSourcedEncrypt(uPolicy string, authorities map[string]*Authority) (*Cipher, error) {
	policy := new(Policy)
	d.growNewPolicy(uPolicy, d.CurveParam.GetNewZn(), policy)

	n := len(policy.AccessStruct.LsssMatrix) - 1
	l := len(policy.AccessStruct.LsssMatrix[0])
	v := make([]*PBC.Element, l, l)
	w := make([]*PBC.Element, l, l)
	c1s := make([]*PBC.Element, n, n)
	c2s := make([]*PBC.Element, n, n)
	c3s := make([]*PBC.Element, n, n)
	c4s := make([]*PBC.Element, n, n)
	
	v[0] = d.CurveParam.GetNewZn()
	w[0] = d.CurveParam.GetNewZn().NewFieldElement().Set0()
	for i := 1; i < l; i++ {
		v[i] = d.CurveParam.GetNewZn()
		w[i] = d.CurveParam.GetNewZn()
	}
	
	for i := 0; i < n; i++ {

		attrStr := policy.AccessStruct.PolicyMaps[i+1]

		authorityName := GetAuthorityNameFromAttrName(attrStr)
		authority, ok := authorities[authorityName]
		if !ok {
			return nil, fmt.Errorf("authority not found, error when %s", attrStr)
		}

		apk := authority.GetAPKMap()[attrStr]
		if apk == nil {
			return nil, fmt.Errorf("pk not found, error when %s", attrStr)
		}

		t := d.CurveParam.GetNewZn()

		AiV := policy.AccessStruct.LsssMatrixDotMulVector(i+1, v)

		tmp := apk.GetGalpha().NewFieldElement().PowZn(apk.GetGalpha(), t)
		c1 := d.G.NewFieldElement().PowZn(d.G, AiV)
		c1.ThenMul(tmp)


		tmp = t.NewFieldElement().Neg(t)
		c2 := d.G.NewFieldElement().PowZn(apk.GetGgamma(), tmp)

		Aiw := policy.AccessStruct.LsssMatrixDotMulVector(i+1, w)
		tmp1 := apk.GetGbeta().NewFieldElement().PowZn(apk.GetGbeta(),t)
		tmp2 := d.G.NewFieldElement().PowZn(d.G,Aiw)
		c3 := tmp1.NewFieldElement().Mul(tmp1, tmp2)


		tmp = d.CurveParam.GetG1FromStringHash(attrStr,sha256.New())
		c4 := tmp.NewFieldElement().PowZn(tmp,t)


		c1s[i] = c1
		c2s[i] = c2
		c3s[i] = c3
		c4s[i] = c4

	}
	fmt.Println("DABE Encrypt success")
	return &Cipher{
		C00:        nil,
		C01:		nil,
		C1s:        c1s,
		C2s:        c2s,
		C3s:        c3s,
		C4s:        c4s,
		CipherText1: nil,
		CipherText2: nil,
		Policy:     policy,
		S:			v[0],
	}, nil
}

func (d *DABE) HEncrypt(m1 string, m2 string, d0 *PBC.Element, cipher *Cipher, authorities map[string]*Authority) (*Cipher, error) {
	fmt.Println("DABE Encrypt start")
	aesKey1 := d.EGG.NewFieldElement().Rand()
	aesKey2 := d.EGG.NewFieldElement().Rand()

	aesCipherText1, err := AES.AesEncrypt([]byte(m1), (aesKey1.Bytes())[0:32])
	aesCipherText2, err := AES.AesEncrypt([]byte(m2), (aesKey2.Bytes())[0:32])
	if err != nil {
		return nil, fmt.Errorf("AES encrypt error\n")
	}

	policy := cipher.Policy


	n := len(policy.AccessStruct.LsssMatrix) - 1

	c1s := make([]*PBC.Element, n, n)
	c2s := make([]*PBC.Element, n, n)
	c3s := make([]*PBC.Element, n, n)
	c4s := make([]*PBC.Element, n, n)

	s := d.CurveParam.GetNewZn()
	sum := s.NewFieldElement().Mul(s, cipher.S)


	c00 := aesKey1.Mul(aesKey1, d.EGG.NewFieldElement().PowZn(d.EGG, sum))
	tmp := s.NewFieldElement().Add(sum, d0)
	c01 := aesKey2.Mul(aesKey2, d.EGG.NewFieldElement().PowZn(d.EGG, tmp))

	for i := 0; i < n; i++ {

		attrStr := policy.AccessStruct.PolicyMaps[i+1]

		authorityName := GetAuthorityNameFromAttrName(attrStr)
		authority, ok := authorities[authorityName]
		if !ok {
			return nil, fmt.Errorf("authority not found, error when %s", attrStr)
		}

		apk := authority.GetAPKMap()[attrStr]
		if apk == nil {
			return nil, fmt.Errorf("pk not found, error when %s", attrStr)
		}


		c1 := cipher.C1s[i].ThenPowZn(s)
		c2 := cipher.C2s[i].ThenPowZn(s)
		c3 := cipher.C3s[i].ThenPowZn(s)
		c4 := cipher.C4s[i].ThenPowZn(s)

		c1s[i] = c1
		c2s[i] = c2
		c3s[i] = c3
		c4s[i] = c4
		// c5s[i] = c5
	}
	fmt.Println("DABE Encrypt success")
	return &Cipher{
		C00:        c00,
		C01:		c01,
		C1s:        c1s,
		C2s:        c2s,
		C3s:        c3s,
		C4s:        c4s,
		CipherText1: aesCipherText1,
		CipherText2: aesCipherText2,
		Policy:     policy,
	}, nil
}

func (d *DABE) OutsourceDecrypt(cipher *Cipher, privateKeys map[string]*TK) (*PBC.Element, error) {
	fmt.Println("DABE OutsourceDecrypt start")


	policy := cipher.Policy

	n := len(policy.AccessStruct.LsssMatrix) - 1
	attrs := make([]string, 0, 0) 

	for key, _ := range privateKeys {
		attrs = append(attrs, key)
	}

	cxs, err := d.genCoefficient(attrs, policy)
	if err != nil {
		return nil, err
	}


	result := d.EGG.NewFieldElement().Set1()
	for i := 0; i < n; i++ {
		if cxs[i+1] == nil {
			continue
		}

		attrStr := policy.AccessStruct.PolicyMaps[i+1]

		
		tk0 := d.CurveParam.GetZnFromStringHash("kiki", sha256.New())
		tk1 := privateKeys[attrStr].TK1
		tk2 := privateKeys[attrStr].TK2
		tk3 := privateKeys[attrStr].TK3
		tk4 := privateKeys[attrStr].TK4
		

		temp1 := cipher.C2s[i].NewFieldElement().PowZn(cipher.C2s[i],tk0)
		eq1 :=  d.EGG.NewFieldElement().Pair(tk1,temp1)


		eq2 := d.EGG.NewFieldElement().Pair(tk4,cipher.C3s[i])


		eq3 := d.EGG.NewFieldElement().Pair(cipher.C4s[i],tk2)

		eq4 := eq1.ThenMul(eq3)
		eq5 := eq2.ThenMul(eq4)
		eq6 := d.EGG.NewFieldElement().Pair(cipher.C1s[i],tk3)
		temp1 = eq5.ThenMul(eq6)
		temp1 = temp1.NewFieldElement().PowZn(temp1,cxs[i+1])

		result.ThenMul(temp1)
	}

	return result, nil
}

func (d *DABE) LocalDecrypt(ct *PBC.Element, cipher *Cipher, n *PBC.Element) ([]byte, *PBC.Element, error) {
	newCT := ct.NewFieldElement().PowZn(ct, n)
	aesKey1 := d.EGG.NewFieldElement().Set(cipher.C00).ThenDiv(newCT)
	if aesKey1 == nil {
		return nil, nil, fmt.Errorf("User policy not match,decrypt failed.\n")
	}
	if len(aesKey1.Bytes()) <= 32 {
		return nil, nil, fmt.Errorf("invalid aeskey:: decrypt failed.\n")
	}
	M1, err := AES.AesDecrypt(cipher.CipherText1, (aesKey1.Bytes())[0:32])
	if err != nil || M1 == nil {
		return nil, nil, fmt.Errorf("aes error:: decrypt failed.\n")
	}
	fmt.Println("DABE LocalDecrypt success")
	return M1, newCT, nil
}

func (d *DABE) SecondLevelDecrypt(d0 *PBC.Element, cipher *Cipher, result *PBC.Element) ([]byte, error) {
	tmp := d.EGG.NewFieldElement().Mul(d0, result)
	aesKey2 := d.EGG.NewFieldElement().Set(cipher.C01).ThenDiv(tmp)
	if aesKey2 == nil {
		return nil, fmt.Errorf("User policy not match,decrypt failed.\n")
	}
	if len(aesKey2.Bytes()) <= 32 {
		return nil, fmt.Errorf("invalid aeskey:: decrypt failed.\n")
	}
	M2, err := AES.AesDecrypt(cipher.CipherText2, (aesKey2.Bytes())[0:32])
	if err != nil || M2 == nil {
		return nil, fmt.Errorf("aes error:: decrypt failed.\n")
	}
	fmt.Println("DABE LocalDecrypt success")
	return M2, nil
}

func (d *DABE) Trace(target string, privateKeys map[string]*USK, authorities map[string]*Authority) (bool, error) {

	for attr, usk := range privateKeys{
		uid := usk.SK0
		hashUid := d.CurveParam.GetG1FromStringHash(uid,sha256.New())
		sk0 := d.CurveParam.GetZnFromStringHash(uid,sha256.New())
		sk1 := usk.SK1
		sk2 := usk.SK2

		apk := authorities[GetAuthorityNameFromAttrName(attr)].GetAPKMap()[attr]
		Gbeta := apk.GetGbeta()
		Ggamma := apk.GetGgamma()
		Galpha := apk.GetGalpha()
		EGGalpha := d.EGG.NewFieldElement().Pair(Galpha, d.G)

		temp1 := Ggamma.NewFieldElement().PowZn(Ggamma, sk0)
		eq1 := d.EGG.NewFieldElement().Pair(sk1,temp1)

		temp2 := d.EGG.NewFieldElement().Pair(hashUid,Gbeta).ThenPowZn(sk0)
		temp3 := d.CurveParam.GetG1FromStringHash(attr,sha256.New())
		temp3 = d.EGG.NewFieldElement().Pair(temp3,sk2)
		eq2 := temp2.ThenMul(EGGalpha).ThenMul(temp3)

		if eq1.Equals(eq2) {
			if uid != target {
				return false, fmt.Errorf("USK have the chance of being robbed")
			}
		} else {
			return false, fmt.Errorf("USK can't pass key sanity check")
		}
	}
	return true, nil
}

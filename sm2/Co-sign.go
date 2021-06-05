package sm2

import (
	"fmt"
	"io"
	"log"
)

/*
准备临时私钥和公钥
A生成Ra Ra‘(Ra'=Ra_b)
RA = kA ⋅ P，
RA '= kA ⋅ pkB
*/
func GenerateRa(random io.Reader, pkb PublicKey) (Ra, Ra_b *PrivateKey, err error) {
	/*raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	ka := new(big.Int).SetBytes(raBuf)



	*/

	curve := P256Sm2() //曲线类型
	ka, err := randFieldElement(curve, random)
	if err != nil {
		return nil, nil, err
	}

	Ra = new(PrivateKey)
	Ra.Curve = curve
	Ra_b = new(PrivateKey)
	Ra.X, Ra.Y = curve.ScalarBaseMult(ka.Bytes()) //RA = kA ⋅ P
	Ra.D = ka
	Ra_b.X, Ra_b.Y = curve.ScalarMult(pkb.X, pkb.Y, ka.Bytes()) //RA '= kA ⋅ pkB
	if Ra.X == nil || Ra_b.X == nil {
		return nil, nil, fmt.Errorf("公钥生成失败")
	}

	return Ra, Ra_b, err
}

/*
准备临时私钥和公钥 rb.d
验证RA = dB∙RA '
计算RB = kB∙pkA RB '= kB∙P
*/
func GenerateRb(random io.Reader, db *PrivateKey, Ra, Ra_b PublicKey, Pka PublicKey) (Rb, Rb_a *PrivateKey, err error) {
	curve := P256Sm2()
	kb, err := randFieldElement(curve, random)
	if err != nil {
		log.Fatal("验证Ra失败")

	}
	/*
	       //测试ra
	   	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
	   		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
	   		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
	   		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}
	   	kb := new(big.Int).SetBytes(rbBuf)
	*/
	Rb = new(PrivateKey)
	Rb.Curve = curve
	Rb.D = kb
	x2, y2 := curve.ScalarMult(Ra.X, Ra.Y, db.D.Bytes())
	fmt.Printf("db%x", db.D)
	if x2.Cmp(Ra_b.X) != 0 || y2.Cmp(Ra_b.Y) != 0 {
		fmt.Println("Ra 验证失败")
		return nil, nil, fmt.Errorf("Ra 验证失败")
	}
	Rb_a = new(PrivateKey)
	Rb.Curve = curve
	Rb.X, Rb.Y = curve.ScalarMult(Pka.X, Pka.Y, kb.Bytes()) //RB = kB∙pkA

	Rb_a.X, Rb_a.Y = curve.ScalarBaseMult(kb.Bytes()) //RB '= kB∙P
	if Rb.X == nil || Rb_a.X == nil {
		return nil, nil, fmt.Errorf("公钥生成失败")
	}

	return Rb, Rb_a, err
}

/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"testing"
)

func TestMulsign(t *testing.T) {

	testRetFile, err := os.OpenFile("./mutilresult.txt", os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Println(err)
	}
	/*
		daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
			0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
			0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
			0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
		dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
			0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
			0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
			0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
		/*
			raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
				0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
				0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
				0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

			rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
				0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
				0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
				0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}
	*/
	/*

		curve.ScalarBaseMult(daBuf)
		Da := new(PrivateKey)
		Da.PublicKey.Curve = curve
		Da.D = new(big.Int).SetBytes(daBuf)
		Da.PublicKey.X, Da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

		Db := new(PrivateKey)
		Db.PublicKey.Curve = curve
		Db.D = new(big.Int).SetBytes(dbBuf)
		Db.PublicKey.X, Db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)
	*/
	curve := P256Sm2()
	msg := []byte("test")

	Da, err := GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	Db, err := GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}

	Ra, Ra_b, err := GenerateRa(rand.Reader, Db.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	Rb, Rb_a, err := GenerateRb(rand.Reader, Db, Ra.PublicKey, Ra_b.PublicKey, Da.PublicKey)
	if err != nil {
		log.Fatal("生成rb失败")

	}
	x2, _ := Ra.Curve.ScalarMult(Rb_a.X, Rb_a.Y, Da.D.Bytes())
	if x2.Cmp(Rb.X) != 0 {
		fmt.Println("验证rb失败")
	}
	pubK := GenerateSharedpuk(Db.PublicKey, Da.D)

	R, r1, s1, err := MutilSignA(Ra, Rb.PublicKey, Da.D, msg, default_uid, rand.Reader)
	_, err = fmt.Fprintf(testRetFile, "Ra_x:%x\nRa_y:%x\nRb_x:%x\nRb_y:%x\nR_x:%x\nR_y:%x\npk_x:%x\npk_y:%x\n", Ra.X, Ra.Y, Rb.X, Rb.Y, R.X, R.Y, pubK.X, pubK.Y)
	t1 := MutilSignB(s1, Db, Rb)
	fmt.Fprintf(testRetFile, "r1:%x\ns1:%x\n", r1, s1)

	r, s, err := MutilSignA2(curve.Params().N, t1, r1)

	fmt.Fprintf(testRetFile, "t1:%x\nr:%x\ns:%x\n", t1, r, s)

	Sign, err := asn1.Marshal(sm2Signature{r, s})

	fmt.Fprintf(testRetFile, "签名信息\nsign:%x\nRx:%x\nRy:%x\n", Sign, R.X, R.Y)

	if err != nil {
		log.Println(err)
	}

	R1, ok := VeriyR(R, pubK, t1, s)
	if ok {
		fmt.Println("R‘=R")
		fmt.Printf("验证公钥：x：%x\n y:%x\n", R1.X, R1.Y)
	}

	ok = R1.MVerify(msg, Sign)
	if err != nil {
		log.Println(err)
	}
	if ok != true {
		fmt.Printf("签名验证 error\n")
	} else {
		fmt.Printf("签名验证 ok\n")
	}
}

func TestSm2(t *testing.T) {

	priv, err := GenerateKey(rand.Reader) // 生成密钥对
	fmt.Println("pri-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("1234567")
	d0, err := pub.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.DecryptAsn1(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)

	msg, _ = ioutil.ReadFile("msg.txt") // 从文件读取数据
	fmt.Println(string(msg))
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile("TestResult.txt", sign, os.FileMode(0644))
	if err != nil {
		t.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("TestResult.txt")
	msg1 := []byte("123123123231231231")
	fmt.Println(string(msg1))

	ok := priv.Verify(msg1, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	pubKey := priv.PublicKey
	ok = pubKey.Verify(msg1, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, _ := priv.Sign(nil, msg, nil) // 签名

		priv.Verify(msg, sign) // 密钥验证
	}
}

func TestKEB2(t *testing.T) {
	ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	expk := []byte{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84,
		0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}

	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

	k1, Sb, S2, err := KeyExchangeB(16, ida, idb, db, &da.PublicKey, rb, &ra.PublicKey)
	if err != nil {
		t.Error(err)
	}
	k2, S1, Sa, err := KeyExchangeA(16, ida, idb, da, &db.PublicKey, ra, &rb.PublicKey)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(k1, k2) != 0 {
		t.Error("key exchange differ")
	}
	if bytes.Compare(k1, expk) != 0 {
		t.Errorf("expected %x, found %x", expk, k1)
	}
	if bytes.Compare(S1, Sb) != 0 {
		t.Error("hash verfication failed")
	}
	if bytes.Compare(Sa, S2) != 0 {
		t.Error("hash verfication failed")
	}
}

/*
func TestMulsig(t *testing.T) {
	msg := []byte("test")

		ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
			'1', '2', '3', '4', '5', '6', '7', '8'}
		idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
			'1', '2', '3', '4', '5', '6', '7', '8'}
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

	da.PublicKey.Curve = curve
	fmt.Printf("pbA %x\r\n:", da.PublicKey)

	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	//fmt.Printf("%v\n", da.Curve.IsOnCurve(da.X, da.Y)) // 验证是否为sm2的曲线

	ra_b := new(PublicKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)

	//验证
	//fmt.Printf("priRA %x\r\n:", ra.D)

	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)
	rb = new(PrivateKey)
	rb_a := new(PublicKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	//fmt.Printf("priB %x\r\n:", db.D)
	//fmt.Printf("%v\n", db.Curve.IsOnCurve(db.X, db.Y)) // 验证是否为sm2的曲线

	//Bob 发送 pkB 给 Alice 计算 pk = dA dB P - P
	pubK := new(PublicKey)
	pubkX, pubkY := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, (new(big.Int).Mul(da.D, db.D)).Bytes())
	negY := new(big.Int).Neg(curve.Params().Gy)
	fmt.Println("neg:", curve.Params().Gy, negY)
	pubK.X, pubK.Y = curve.Add(pubkX, pubkY, curve.Params().Gx, negY)
	x5, y5 := curve.Add(pubK.X, pubK.Y, curve.Params().Gx, curve.Params().Gy)
	if (x5.Cmp(pubkX) | y5.Cmp(pubkY)) != 0 {
		fmt.Println("不相等")
		fmt.Println(x5, y5)
		fmt.Println(pubkX, pubkY)
	}

	//_, _ = pk_x, pk_y

	//Alice 和 Bob 分别存储 ( pk，dA，pkB) 和 ( pk，dB，pkA)
	//Alice
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf) //
	//fmt.Printf("raIsOnCurve:%v\n", db.Curve.IsOnCurve(ra.X, ra.Y)) // 验证是否为sm2的曲线
	ra_b.X, ra_b.Y = curve.ScalarMult(db.PublicKey.X, db.PublicKey.Y, raBuf)

	//fmt.Printf("rab IsOnCurve:%v\n", db.Curve.IsOnCurve(ra_b.X, ra_b.Y)) // 验证是否为sm2的曲线

	//Bob
	//验证RA' = dB∙RA
	//发送rb，rb_a
	x2, _ := curve.ScalarMult(ra.X, ra.Y, dbBuf)
	if x2.Cmp(ra_b.X) != 0 {
		fmt.Println("Ra验证失败")
	}

	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarMult(da.X, da.Y, rbBuf) //
	rb_a.X, rb_a.Y = curve.ScalarBaseMult(rbBuf)
	//alice 验证RB = dA ∙RB'
	//计算椭圆曲线群元素R'=RA+
	//RB = (xA，yA )，计 算 r =H (ZA||M) +xA mod q 和
	//s'= (kA + r) d -1
	//A mod q，并将s'发送给Bob.
	x2, _ = curve.ScalarMult(rb_a.X, rb_a.Y, daBuf)
	if x2.Cmp(rb.X) != 0 {
		fmt.Println("Rb验证失败")
	}

	R := new(PrivateKey)
	R.PublicKey.Curve = curve
	R.X, R.Y = curve.Add(ra.X, ra.Y, rb.X, rb.Y) //线群元素R'=RA+ RB = (xA，yA )

	fmt.Printf("Ra_x:%x\nRa_y:%x\nRb_x:%x\nRb_y:%x\nR_x:%x\nR_y:%x\npk_x:%x\npk_y:%x\n", ra.X, ra.Y, rb.X, rb.Y, R.X, R.Y, pubK.X, pubK.Y)
	if curve.IsOnCurve(R.X, R.Y) == false {
		fmt.Println("R不在曲线")
	}
	curve.IsOnCurve(pubK.X, pubK.Y)
	if curve.IsOnCurve(pubK.X, pubK.Y) == false {
		fmt.Println("pubK不在曲线")
	}

	r1, s1, _ := MutilSignA(R, ra, da, msg, default_uid, rand.Reader)
	fmt.Printf("r1:%x\ns1:%x\n", r1, s1)
	fmt.Printf("RB:%x\n", rb.X)
	t1 := MutilSignB(s1, db,rb)

	r, s, _ := MutilSignA2(t1, r1)

	fmt.Printf("t1:%x\nr:%x\ns:%x\n", t1, r, s)
	sign, _ := asn1.Marshal(sm2Signature{r, s})

	fmt.Printf("sign:%x\n", sign)


	   验证计算


	x1, y1 := curve.Add(ra.X, ra.Y, rb.X, rb.Y)
	x2_1, y2_1 := curve.ScalarBaseMult(ra.D.Bytes())
	x2_2, y2_2 := curve.ScalarMult(da.X, da.Y, rb.D.Bytes())
	x2, y2 := curve.Add(x2_1, y2_1, x2_2, y2_2)
	if x2.Cmp(x1) == 0 && y1.Cmp(y2) == 0 {
		fmt.Println("step 2 正确")
	}
	///step5
	x5_1, y5_1 := curve.ScalarBaseMult(r.Bytes())
	y5_1 = new(big.Int).Neg(y5_1)
	fmt.Println("X5_1", x5_1, y5_1)
	x5_2, y5_2 := curve.ScalarMult(da.Y, da.Y, (new(big.Int).Add(s1, rb.D)).Bytes())
	x5, y5 = curve.Add(x5_1, y5_1, x5_2, y5_2) //=-rp+( s'+ kB)dA P
	if x5.Cmp(x2) == 0 && y5.Cmp(y2) == 0 {
		fmt.Println("step 5 正确")
	}

	fmt.Printf("x1:%x\ny1:%x\nx2:%x\ny2:%x\nx5:%x\ny5:%x\n", x1, y1, x2, y2, x5, y5)

	//验证t *db=（s'+kb）
	///

	db_t := new(big.Int).Mul(db.D, t1)
	db_t.Mod(db_t, curve.Params().N)
	s_add_kb := new(big.Int).Add(s1, rb.D)
	s_add_kb.Mod(s_add_kb,curve.Params().N)
	if s_add_kb.Cmp(db_t) == 0 {
		fmt.Printf("t *db=（s'+kb）\n")
	}

	//验证R= s⋅ P + t ⋅ pk = rp+ tdA dB P
	x7_1, y7_1 := curve.ScalarBaseMult(r.Bytes())
	y7_1.Neg(y7_1)
	x73 := (new(big.Int).Mul(t1, db.D))
	x73.Mod(x73, curve.Params().N)

	x7_2, y7_2 := curve.ScalarMult(da.Y, da.Y, x73.Bytes())
	x7, y7 := curve.Add(x7_1, y7_1, x7_2, y7_2)
	if x7.Cmp(R.X) == 0 && y7.Cmp(R.Y) == 0 {
		fmt.Println("step 9_2=5_2 正确")
	}

	RR := new(PublicKey)
	RR.Curve = curve
	RR.X, RR.Y = curve.ScalarBaseMult(s.Bytes())
	tt := new(big.Int).Add(r, s)
	tt.Mod(tt, curve.Params().N)
	RR_X, RR_Y := curve.ScalarMult(pubK.X, pubK.Y, tt.Bytes())
	RR.X, RR.Y = curve.Add(RR.X, RR.Y, RR_X, RR_Y)

		fmt.Println(RR.X, R.X)
		if R.Y.Cmp(RR.X) != 0 {
			fmt.Println("R'验证失败")
		}

	ok := R.MVerify(msg, sign)
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	/*

		digest, err := R.Sm3Digest(msg, nil)
		if err != nil {
			fmt.Println("sm3 封装失败")

		}
		r := new(big.Int).SetBytes(digest)
		r.Add(r, R.X)
		r.Mod(r, N)

		//s'= (kA + r) dA^-1 mod q
		s1 := new(big.Int).Add(ra.D, r)
		daInv := new(big.Int).ModInverse(da.D, N)
		s1.Mul(s1, daInv)
		s1.Mod(s1, N)

		//Bob收到s'计算t = (s'+ kB)dB^-1 mod q，
		//并将t发送给Alice.
		t1 := new(big.Int).Add(s1, rb.D)
		dbInv := new(big.Int).ModInverse(db.D, N)
		t1.Mul(t1, dbInv)
		t1.Mod(t1, N)
		//Alice  收到tt以后，计算s= t - r，输出数字签名(r，s).
		s := (new(big.Int).Sub(t1,r))

		 _, _ = r, s
		sig ,_:=asn1.Marshal(sm2Signature{r, s})
		ok :=R.MVerify(msg,sig)
		if ok != true {
			fmt.Printf("Verify error\n")
		} else {
			fmt.Printf("Verify ok\n")
		}


		//验证签名
		//R'= s'⋅ P + t ⋅ Q = (x1 '，y1 ')，
		R1 := new(PublicKey)
		R1.X, R1.Y =curve.ScalarMult(pk_x,pk_y,t1.Bytes())
		R1_X, R1_Y := curve.ScalarBaseMult(s1.Bytes())
		R1.X, R1.Y = curve.Add(R1.X, R1.Y,R1_X, R1_Y)
		fmt.Println(R1.X)
		fmt.Println(R.X)

		if R1.X.Cmp(R.X) != 0 {
			fmt.Println("R' 验证失败")
		}

		za, err := ZA(R1, default_uid)//具体算法见国标2-5.5 ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
		if err != nil {
			fmt.Println("解析za失败")
		}
		e, err := msgHash(za, msg)//e' = Hash (Za||M')

		r_v := e.Add(e, R1.X)
		r_v.Mod(r_v, N)
		fmt.Println("r_v:",r_v)
		fmt.Println("r:",r)



}




*/

func TestSign(t *testing.T) {
	msg := []byte("test")
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)

	//Bob 发送 pkB 给 Alice 计算 pk = dA dB P - P
	//减运算没问题
	pubK := new(PublicKey)
	pubkX1, pubkY1 := curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, (new(big.Int).Mul(da.D, db.D)).Bytes())
	negY := new(big.Int).Neg(curve.Params().Gy)
	pubK.X, pubK.Y = curve.Add(pubkX1, pubkY1, curve.Params().Gx, negY)
	x5, y5 := curve.Add(pubK.X, pubK.Y, curve.Params().Gx, curve.Params().Gy)

	if (x5.Cmp(pubkX1) | y5.Cmp(pubkY1)) != 0 {
		fmt.Println("不相等")
		fmt.Println(x5, y5)
		fmt.Println(pubkX1, pubkY1)
	}

	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)

	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)

	da.PublicKey.Curve = curve

	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)

	ra_b := new(PublicKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)

	//验证
	//fmt.Printf("priRA %x\r\n:", ra.D)

	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)
	rb = new(PrivateKey)
	rb_a := new(PublicKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)

	//Alice 和 Bob 分别存储 ( pk，dA，pkB) 和 ( pk，dB，pkA)
	//Alice
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf) //
	//fmt.Printf("raIsOnCurve:%v\n", db.Curve.IsOnCurve(ra.X, ra.Y)) // 验证是否为sm2的曲线
	ra_b.X, ra_b.Y = curve.ScalarMult(db.PublicKey.X, db.PublicKey.Y, raBuf)

	//Bob
	//验证RA' = dB∙RA
	//发送rb，rb_a
	x2, y2 := curve.ScalarMult(ra.X, ra.Y, dbBuf)
	if x2.Cmp(ra_b.X) != 0 || y2.Cmp(ra_b.Y) != 0 {
		log.Fatal("Ra验证失败")
	}
	//算 RB = kB∙pkA，RB '= kB∙P
	rb.X, rb.Y = curve.ScalarMult(da.X, da.Y, rbBuf) //
	rb_a.X, rb_a.Y = curve.ScalarBaseMult(rbBuf)
	//alice 验证RB = dA ∙RB'
	//计算椭圆曲线群元素R'=RA+
	//RB = (xA，yA )，计 算 r =H (ZA||M) +xA mod q 和
	//s'= (kA + r) d -1
	//A mod q，并将s'发送给Bob.
	x2, _ = curve.ScalarMult(rb_a.X, rb_a.Y, daBuf)
	if x2.Cmp(rb.X) != 0 {
		fmt.Println("Rb验证失败")
	}

	R := new(PublicKey)
	R.Curve = curve
	R.X, R.Y = curve.Add(ra.X, ra.Y, rb.X, rb.Y) //线群元素R'=RA+ RB = (xA，yA )
	N := R.Params().N

	digest, err := R.Sm3Digest(msg, nil)
	if err != nil {
		fmt.Println("sm3 封装失败")
	}
	r := new(big.Int).SetBytes(digest)
	r.Add(r, R.X)
	r.Mod(r, N)

	//s'= (kA + r) dA^-1 mod q
	s1 := new(big.Int).Add(ra.D, r)
	fmt.Printf("r1:%x\ns1:%x\n", r, s1)
	daInv := new(big.Int).ModInverse(da.D, N)
	s1.Mul(s1, daInv)
	s1.Mod(s1, N)

	//Bob收到s'计算t = (s'+ kB)dB^-1 mod q，
	//并将t发送给Alice.
	t1 := new(big.Int).Add(s1, rb.D)
	dbInv := new(big.Int).ModInverse(db.D, N)
	t1.Mul(t1, dbInv)
	t1.Mod(t1, N)
	//Alice  收到tt以后，计算s= t - r，输出数字签名(r，s).
	s := (new(big.Int).Sub(t1, r))

	fmt.Printf("t1:%x\nr:%x\ns:%x\n", t1, r, s)
	sig, _ := asn1.Marshal(sm2Signature{r, s})

	//验证签名
	//R'= s'⋅ P + t ⋅ Q = (x1 '，y1 ')=s⋅ P + t ⋅ pk
	R1 := new(PublicKey)
	R1.Curve = curve
	//	tt := new(big.Int).Add(r, s)
	//	tt.Mod(tt, curve.Params().N)
	R1.X, R1.Y = curve.ScalarMult(pubK.X, pubK.Y, t1.Bytes())
	R1_X, R1_Y := curve.ScalarBaseMult(s.Bytes())
	R1.X, R1.Y = curve.Add(R1.X, R1.Y, R1_X, R1_Y)
	if R1.X.Cmp(R.X) != 0 {
		fmt.Println("R''' 验证失败")
	}

	R12, _ := VeriyR(R, pubK, t1, s)
	if R12.X.Cmp(R.X) != 0 {
		fmt.Println("R''' 验证失败")
	}

	fmt.Printf("Ra_x:%x\nRa_y:%x\nRb_x:%x\nRb_y:%x\nR_x:%x\nR_y:%x\npk_x:%x\npk_y:%x\n", ra.X, ra.Y, rb.X, rb.Y, R.X, R.Y, pubK.X, pubK.Y)
	fmt.Printf("r:%x\ns:%x\n", r, s)
	fmt.Println("签名信息")
	fmt.Printf("sign:%x\nRx:%x\nRy:%x\n", sig, R.X, R.Y)

	ok := R.MVerify(msg, sig)
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}

func BenchmarkMutulSig(b *testing.B) {

	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}

	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}
	msg := []byte("test")
	curve := P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)
	db := new(PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)
	ra := new(PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf)
	rb := new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf)
	rb = new(PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarMult(da.X, da.Y, rbBuf) //
	b.ResetTimer()
	pubK := GenerateSharedpuk(db.PublicKey, da.D)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		R, r1, s1, err := MutilSignA(ra, rb.PublicKey, da.D, msg, default_uid, rand.Reader)
		//_, err = fmt.Fprintf(testRetFile, "Ra_x:%x\nRa_y:%x\nRb_x:%x\nRb_y:%x\nR_x:%x\nR_y:%x\npk_x:%x\npk_y:%x\n", ra.X, ra.Y, rb.X, rb.Y, R.X, R.Y, pubK.X, pubK.Y)
		//	fmt.Fprintf(testRetFile, "RB:%x\n", rb.X)
		t1 := MutilSignB(s1, db, rb)
		//fmt.Fprintf(testRetFile, "r1:%x\ns1:%x\n", r1, s1)

		r, s, err := MutilSignA2(curve.Params().N, t1, r1)

		//	fmt.Fprintf(testRetFile, "t1:%x\nr:%x\ns:%x\n", t1, r, s)

		Sign, err := asn1.Marshal(sm2Signature{r, s})
		//fmt.Fprintf(testRetFile, "签名信息\n")

		//	fmt.Fprintf(testRetFile, "sign:%x\nRx:%x\nRy:%x\n", Sign, R.X, R.Y)

		if err != nil {
			log.Println(err)
		}

		R1, ok := VeriyR(R, pubK, t1, s)
		if ok {
			//fmt.Println("R‘=R")
			//fmt.Printf("验证公钥：x：%x\n y:%x\n", R1.X, R1.Y)

		}

		//	fmt.Printf("签名信息%x\n", Sign)

		ok = R1.MVerify(msg, Sign)
		if err != nil {
			log.Println(err)
		}
		if ok != true {
			//fmt.Printf("签名验证 error\n")
		} else {
			//fmt.Printf("签名验证 ok\n")
		}

	}

}

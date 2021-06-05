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

// reference to ecdsa
import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm3"
	"io"
	"math/big"
)

// sm2SignDefaultUserID 代表sm2算法默认的加密操作用户A的ID编码(详见国标5-A.1)和SM2使用规范(GB/T 35276-2017第10部分)
var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

// PublicKey 代表SM2算法的公钥类:
// (1) X,Y 为P点（有限素数域上基点G的D倍点)坐标
// (2) Curve 为SM2算法的椭圆曲线
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

//PrivateKey 代表SM2算法的私钥类:
// (1) D代表公钥P点相对于基点G的倍数
// (2) Curve 为SM2算法的椭圆曲线
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// sm2Signature 代表SM2算法的数字签名类。
type sm2Signature struct {
	R, S *big.Int
}

type sm2Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s

func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sm2Sign(priv, msg, nil, random)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func MSign(priv *PrivateKey, ra *PrivateKey, da *PrivateKey, rb *PrivateKey, db *PrivateKey, random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error) {

	r, s, err := MutilSign(priv, ra, da, rb, default_uid, msg, random)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})

}

func MutilSign(priv *PrivateKey, ra *PrivateKey, da *PrivateKey, rb *PrivateKey, uid []byte, msg []byte, random io.Reader) (r, s *big.Int, err error) {
	c := priv.PublicKey.Curve
	N := c.Params().N
	var k, s1 *big.Int

	digest, err := priv.PublicKey.Sm3Digest(msg, uid) //预处理1、2
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)

	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	for {
		k, err = randFieldElement(c, random) //随机数l
		if err != nil {
			return nil, nil, err
		}
		r = new(big.Int).Add(e, priv.PublicKey.X)
		r = r.Mod(e, N)
		if r.Sign() != 0 {
			if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
				break
			}
		}
	}
	//s'= (kA + r) dA^-1 mod q
	//s'发给bob
	s1 = new(big.Int).Add(ra.D, r)
	daInv := new(big.Int).ModInverse(da.D, N)
	s1.Mul(s1, daInv)
	s1.Mod(s1, N)

	//bob收到s‘将t发送给Alice.
	t := new(big.Int).Add(s1, rb.D)
	dbInv := new(big.Int).ModInverse(rb.D, N)
	t.Mul(t, dbInv)
	t.Mod(t, N)
	//Alice收到t以后

	s = new(big.Int).Sub(t, r)
	if s.Sign() != 0 {
	}
	return r, s, err

}

/*
puk对方公钥
private 自己的私钥
*/
func GenerateSharedpuk(puk PublicKey, privatekey *big.Int) (sharedPubkey *PublicKey) {
	///共同公钥pk
	pubK := new(PublicKey)
	pubK.Curve = sm2P256
	pubkX, pubkY := pubK.ScalarMult(puk.X, puk.Y, privatekey.Bytes())
	negY := new(big.Int).Neg(pubK.Params().Gy)
	pubK.X, pubK.Y = pubK.Add(pubkX, pubkY, pubK.Params().Gx, negY)
	return pubK

}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign) // 为SM2将签名对象反序列化函数，即将符合ASN.1标准DER编码规则的字节串反序列化为SM2签名对象。
	if err != nil {
		return false
	}
	return Sm2Verify(pub, msg, default_uid, sm2Sign.R, sm2Sign.S)
}

func (pub *PublicKey) MVerify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign) // 为SM2将签名对象反序列化函数，即将符合ASN.1标准DER编码规则的字节串反序列化为SM2签名对象。
	if err != nil {
		return false
	}

	return MultiVerify(pub, msg, default_uid, sm2Sign.R, sm2Sign.S)
}

func MultiVerify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	one := new(big.Int).SetInt64(1)
	//校验 1 <= r' < n (国标2-7.1.B1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}

	za, err := ZA(pub, uid) //具体算法见国标2-5.5 ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg) //e' = Hash (Za||M')
	if err != nil {
		return false
	}
	//计r'= //e'+ x1 ' mod q 是否成立
	rr := new(big.Int).Add(e, pub.X)
	rr.Mod(rr, N)
	return rr.Cmp(r) == 0
}

func (pub *PublicKey) Sm3Digest(msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = default_uid
	}

	za, err := ZA(pub, uid) //Z=SM3(ENTL||ID||a||b||x_G||y_G||x_A||y_A)
	if err != nil {
		return nil, err
	}

	e, err := msgHash(za, msg) //e=SM3(Z||M)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}

//****************************Encryption algorithm****************************//
func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

//**************************Key agreement algorithm**************************//
// KeyExchangeB 协商第二部，用户B调用， 返回共享密钥k
func KeyExchangeB(klen int, ida, idb []byte, priB *PrivateKey, pubA *PublicKey, rpri *PrivateKey, rpubA *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priB, pubA, rpri, rpubA, false)
}

// KeyExchangeA 协商第二部，用户A调用，返回共享密钥k
func KeyExchangeA(klen int, ida, idb []byte, priA *PrivateKey, pubB *PublicKey, rpri *PrivateKey, rpubB *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priA, pubB, rpri, rpubB, true)
}

//****************************************************************************//

/*
验证RB = dA∙RB '
计算R'= RA + RB = ( xA ,yA )
计算
ZA = H ( ENTL|| IDA ||a|| b ||P||pk )
计算r = H (ZA||M) + xA mod q
计算s'= (kA + r) dA-1 mod q
输出s'
*/
func MutilSignA(ra *PrivateKey, rb PublicKey, da *big.Int, msg, uid []byte, random io.Reader) (R *PublicKey, r, s *big.Int, err error) {
	R = new(PublicKey)
	R.Curve = sm2P256
	R.X, R.Y = R.Curve.Add(ra.X, ra.Y, rb.X, rb.Y) //线群元素R'=RA+ RB = (xA，yA )
	c := R.Curve
	N := c.Params().N
	var k, s1 *big.Int

	digest, err := R.Sm3Digest(msg, uid) //预处理1、2
	if err != nil {
		return nil, nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)

	if N.Sign() == 0 {
		return nil, nil, nil, errZeroParam
	}
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, random) //随机数l
			if err != nil {
				return nil, nil, nil, err
			}
			r = new(big.Int).Add(e, R.X)
			r = r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}
			//s'= (kA + r) dA^-1 mod q
			//s'发给bob

		}
		s1 = new(big.Int).Add(ra.D, r)
		s1.Mod(s1, N)
		daInv := new(big.Int).ModInverse(da, N)
		s1.Mul(s1, daInv)
		s1.Mod(s1, N)
		return R, r, s1, err

	}

}

func MutilSignA2(N, t, r1 *big.Int) (r, s *big.Int, err error) {

	s = new(big.Int).Sub(t, r1)
	s.Mod(s, N)
	if s.Sign() == 0 {
		return nil, nil, nil
	}
	return r1, s, err

}

func MutilSignB(s1 *big.Int, db *PrivateKey, rb *PrivateKey) *big.Int {
	c := db.PublicKey.Curve
	N := c.Params().N
	//bob收到s‘将t发送给Alice.
	t := new(big.Int).Add(s1, rb.D)
	t.Mod(t, N)
	dbInv := new(big.Int).ModInverse(db.D, N)
	t.Mul(t, dbInv)
	t.Mod(t, N)
	//Alice收到t以后
	return t

}

func RS2sign(r, s *big.Int) (Sign []byte) {
	Sign, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return nil

	}
	return Sign

}

func VeriyR(R *PublicKey, pubK *PublicKey, t *big.Int, s *big.Int) (R1 *PublicKey, VeriyR_ok bool) {

	//验证签名
	//R'= s'⋅ P + t ⋅ Q = (x1 '，y1 ')=s⋅ P + t ⋅ pk
	R1 = new(PublicKey)
	R1.Curve = sm2P256
	R1.X, R1.Y = R1.Curve.ScalarMult(pubK.X, pubK.Y, t.Bytes())
	R1_X, R1_Y := R1.Curve.ScalarBaseMult(s.Bytes())
	R1.X, R1.Y = R1.Curve.Add(R1.X, R1.Y, R1_X, R1_Y)
	if R1.X.Cmp(R.X) != 0 {
		fmt.Println("R' 验证失败")
		return R1, false
	}
	return R1, true

}

func Sm2Sign(priv *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	digest, err := priv.PublicKey.Sm3Digest(msg, uid) //预处理1、2
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, random) //随机数l
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes()) //(x1, y1) = [k]G (国标2-6.1.A4)
			////算r = (e + x1) mod n
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		//调用标准包math/big封装的取乘法逆元和取模函数计算s = ((1+d)^(-1) * (k - r*d)) mod n,
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	//校验 1 <= r' < n (国标2-7.1.B1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}
	za, err := ZA(pub, uid) //具体算法见国标2-5.5 ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg) //e' = Hash (Za||M')
	if err != nil {
		return false
	}
	//计算 t = (r' + s') mod n, 并校验t<>0 (国标2-7.1.B5)
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	//点(x1', y1') = [s']G + [t]PA
	x1, y1 := c.ScalarBaseMult(s.Bytes())           //[s']G
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes()) //[t]Pa
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N) //R=r
	return x.Cmp(r) == 0
}

/*
    za, err := ZA(pub, uid)
	if err != nil {
		return
	}
	e, err := msgHash(za, msg)
	hash=e.getBytes()
	原来得函数
*/
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	// 调整算法细节以实现SM2
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	e := new(big.Int).SetBytes(hash)
	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

/*
 * sm2密文结构如下:
 *  x
 *  y
 *  hash
 *  CipherText
*返回密文
*/
func Encrypt(pub *PublicKey, data []byte, random io.Reader) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, random) //生成随机数
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())           //点C1=[k]*G
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes()) //kPB=(kPBx, kPBy)
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}
		c = append(c, x1Buf...) // x分量
		c = append(c, y1Buf...) // y分量
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)
		h := sm3.Sm3Sum(tm)                 //C3=(X1||M||Y2)
		c = append(c, h...)                 //C=(C1||C3)
		ct, ok := kdf(length, x2Buf, y2Buf) // 密文  t=KDF(length,x2||y2)
		if !ok {
			continue
		}
		c = append(c, ct...) //C1||C3||C2
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i] //C2=M⊕t
		}
		return append([]byte{0x04}, c...), nil //C=(UnCompress,C1||C3||C2)
	}
}

func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	length := len(data) - 96 //前面96个都是秘文消息
	curve := priv.Curve
	// 读取坐标
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	//校验S点是否为无穷远点(SM2推荐曲线h为1，S点即为C1点, 本步骤可忽略)
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes()) //// 根据私钥(priv.D)和曲线计算倍点[priv.D]C1=(c1x, c1y)

	//不需要验证是否无限点？ 这里面sm2推荐h为1，S点为ci
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...) //后面填充0
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	//// 采用改造后的kdf()函数，计算并获取解密后的明文消息
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	//M'=C2^t(国标4-7.1.B4-B5)
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96] //明文
	}
	//tm=Hash(0
	tm := []byte{} //=Hash{x2||M'||y2}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)
	h := sm3.Sm3Sum(tm)
	//U=C3?
	if bytes.Compare(h, data[64:96]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

// keyExchange 为SM2密钥交换算法的第二部和第三步复用部分，协商的双方均调用此函数计算共同的字节串
// klen: 密钥长度
// ida, idb: 协商双方的标识，ida为密钥协商算法发起方标识，idb为响应方标识
// pri: 函数调用者的密钥
// pub: 对方的公钥
// rpri: 函数调用者生成的临时SM2密钥
// rpub: 对方发来的临时SM2公钥
// thisIsA: 如果是A调用，文档中的协商第三步，设置为true，否则设置为false
// 返回 k 为klen长度的字节串
func keyExchange(klen int, ida, idb []byte, pri *PrivateKey, pub *PublicKey, rpri *PrivateKey, rpub *PublicKey, thisISA bool) (k, s1, s2 []byte, err error) {
	curve := P256Sm2()
	N := curve.Params().N
	x2hat := keXHat(rpri.PublicKey.X) //第一部分的4.2.7 x = 2^w + (x & (2^w-1))转整数
	//tB=（dB+x2`*rB）mod n；
	x2rb := new(big.Int).Mul(x2hat, rpri.D)
	tbt := new(big.Int).Add(pri.D, x2rb)
	tb := new(big.Int).Mod(tbt, N)
	if !curve.IsOnCurve(rpub.X, rpub.Y) {
		err = errors.New("Ra not on curve")
		return
	}
	x1hat := keXHat(rpub.X) //x1`=2^w+(x1&(2^w-1))
	//V=[h*tB](PA+[x1`]RA)=(xv,yv)
	ramx1, ramy1 := curve.ScalarMult(rpub.X, rpub.Y, x1hat.Bytes())
	vxt, vyt := curve.Add(pub.X, pub.Y, ramx1, ramy1)
	vx, vy := curve.ScalarMult(vxt, vyt, tb.Bytes())

	pza := pub
	if thisISA {
		pza = &pri.PublicKey
	}
	za, err := ZA(pza, ida) //ZA：关于用户A的可辨别标识、部分椭圆曲线系统参数和用户A公钥的杂凑值。
	if err != nil {
		return
	}
	zero := new(big.Int)
	if vx.Cmp(zero) == 0 || vy.Cmp(zero) == 0 {
		err = errors.New("V is infinite")
	}
	pzb := pub
	if !thisISA {
		pzb = &pri.PublicKey
	}
	zb, err := ZA(pzb, idb)
	k, ok := kdf(klen, vx.Bytes(), vy.Bytes(), za, zb) //KB=KDF（xv||yv||ZA||ZB，klen）；
	if !ok {
		err = errors.New("kdf: zero key")
		return
	}

	//Hash(0x02‖yV‖Hash(xV‖ZA‖ZB‖x1‖y1‖x2‖y2))
	h1 := BytesCombine(vx.Bytes(), za, zb, rpub.X.Bytes(), rpub.Y.Bytes(), rpri.X.Bytes(), rpri.Y.Bytes())
	if !thisISA {
		h1 = BytesCombine(vx.Bytes(), za, zb, rpri.X.Bytes(), rpri.Y.Bytes(), rpub.X.Bytes(), rpub.Y.Bytes())
	}
	hash := sm3.Sm3Sum(h1)
	h2 := BytesCombine([]byte{0x02}, vy.Bytes(), hash) //S1=Hash(0x02‖yU‖Hash(xU‖ZA‖ZB‖x1‖y1‖x2‖y2))
	S1 := sm3.Sm3Sum(h2)
	h3 := BytesCombine([]byte{0x03}, vy.Bytes(), hash) //S2=Hash(0x03‖yV‖Hash(xV‖ZA‖ZB‖x1‖y1‖x2‖y2))
	S2 := sm3.Sm3Sum(h3)
	return k, S1, S2, nil
}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

//为SM2签名算法的第1步预处理函数，即，以签名方身份标识和公钥信息为基础获取Z值:
// (1) 首2个字节存储用户ID的比特长度ENTL
// (2) 之后存储用户ID的字节串
// (3) 之后顺次存储a, b, XG, YG四个椭圆曲线定义参数
// (4) 之后顺次存储签名方公钥PA点的坐标XA和YA
// (5) 输入参数的接口类hash.Hash，将由SM3算法具体实现，详见调用来源
// (6) 具体算法见国标2-5.5  Z = S M 3H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	Entla := uint16(8 * uidLen)
	za.Write([]byte{byte((Entla >> 8) & 0xFF)})
	za.Write([]byte{byte(Entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
	za.Write(sm2P256.B.Bytes())
	za.Write(sm2P256.Gx.Bytes())
	za.Write(sm2P256.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	//bigIntTo32Bytes,如果少于32位置，前面补0
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

/*
sm2加密，返回asn.1编码格式的密文内容
*/
func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

/*
sm2解密，解析asn.1编码格式的密文内容
*/
func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher)
}

/*
*sm2密文转asn.1编码格式
*sm2密文结构如下:
*  x
*  y
*  hash
*  CipherText
 */
func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	hash := data[64:96]
	cipherText := data[96:]
	return asn1.Marshal(sm2Cipher{x, y, hash, cipherText})
}

/*
sm2密文asn.1编码格式转C1|C3|C2拼接格式
*/
func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher sm2Cipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)          // x分量
	c = append(c, y...)          // y分
	c = append(c, hash...)       // x分量
	c = append(c, cipherText...) // y分
	return append([]byte{0x04}, c...), nil
}

// keXHat 计算 x = 2^w + (x & (2^w-1))
// 密钥协商算法辅助函数
func keXHat(x *big.Int) (xul *big.Int) {
	buf := x.Bytes()
	for i := 0; i < len(buf)-16; i++ {
		buf[i] = 0
	}
	if len(buf) >= 16 {
		c := buf[len(buf)-16]
		buf[len(buf)-16] = c & 0x7f
	}

	r := new(big.Int).SetBytes(buf)
	_2w := new(big.Int).SetBytes([]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return r.Add(r, _2w)
}

func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

//钥派生函数KDF,从一个共享秘密比特串中派生出密钥数据，在密钥协商过程中用于交换所获共享得比特串
func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil) //Hai=Hv(Z||ct)
		//klen/v是整数
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...) //最左边的(klen-(v×klen/v)比特
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

//随意数
func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return k, err
}

func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, random)
	if err != nil {
		return nil, err
	}
	/*修改密钥生成
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)//32+8字节
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	*/
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.Curve = c
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes()) //P=[d]G

	return priv, nil
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return Decrypt(priv, msg)
}

//Client.go
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"log"
	"math/big"
	"net"
	"os"
)

const da = "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
const pa_x = "160e12897df4edb61dd812feb96748fbd3ccf4ffe26aa6f6db9540af49c94232"
const pa_y = "4a7dad08bb9a459531694beb20aa489d6649975e1bfcf8c4741b78b4b223007f"

type ClientA struct {
	Ra  sm2.PrivateKey
	puk sm2.PublicKey
	Da  *big.Int
}

var keyA = ClientA{
	Da: new(big.Int).SetBytes([]byte(da)),
	puk: sm2.PublicKey{
		X: new(big.Int).SetBytes([]byte(pa_x)),
		Y: new(big.Int).SetBytes([]byte(pa_y)),
	},
}

func ClientHandleError(err error, when string) {
	if err != nil {
		fmt.Println(err, when)
		os.Exit(1)
	}

}

func main() {

	//拨号远程地址，简历tcp连接
	conn, err := net.Dial("tcp", "172.22.110.80:9090")
	ClientHandleError(err, "client conn error")
	//预先准备消息缓冲区
	buffer := make([]byte, 1024)
	MulsignA(conn)

	//准备命令行标准输入
	reader := bufio.NewReader(os.Stdin)

	for {
		lineBytes, _, _ := reader.ReadLine()
		conn.Write(lineBytes)
		n, err := conn.Read(buffer)
		ClientHandleError(err, "client read error")

		serverMsg := string(buffer[0:n])
		fmt.Println("服务端msg", serverMsg)
		fmt.Println()
		if serverMsg == "bye" {
			break
		}

	}

}

func MulsignA(conn net.Conn) {

	msg := []byte("test")
	keyMap := Getkey()
	fmt.Println("keymap", keyMap)
	Da := new(sm2.PrivateKey)
	Da.Curve = sm2.P256Sm2()
	Pukb := new(sm2.PublicKey)
	Da.D = new(big.Int).SetBytes(keyMap["da"])
	Da.X = new(big.Int).SetBytes(keyMap["puka_x"])
	Da.Y = new(big.Int).SetBytes(keyMap["puka_y"])
	Pukb.X = new(big.Int).SetBytes(keyMap["pukb_x"])
	Pukb.Y = new(big.Int).SetBytes(keyMap["pukb_y"])

	buffer := make([]byte, 1024)
	//testRetFileA, err := os.OpenFile("./tcpmutilresult.txt", os.O_WRONLY|os.O_CREATE, 0666)
	curve := sm2.P256Sm2()
	//msg := []byte("test")

	Ra, Ra_b, err := sm2.GenerateRa(rand.Reader, *Pukb)
	if err != nil {
		log.Fatal(err)
	}
	sendstr := new(RaData)
	sendstr.Ra_x = Ra.X
	sendstr.Ra_y = Ra.Y
	sendstr.Rab_x = Ra_b.X
	sendstr.Rab_y = Ra_b.Y
	buffer, err = json.Marshal(sendstr)

	conn.Write(buffer)

	n, err := conn.Read(buffer)
	ClientHandleError(err, "client read error")

	MsgB := string(buffer[0:n])
	RecRb := new(RbData)
	json.Unmarshal([]byte(MsgB), &RecRb) //json解析到结构体里面

	Rb := new(sm2.PublicKey)
	Rb_a := new(sm2.PublicKey)

	Rb.X = RecRb.Rb_x
	Rb.Y = RecRb.Rb_y
	Rb_a.X = RecRb.Rba_x
	Rb_a.Y = RecRb.Rba_y

	x2, _ := Da.ScalarMult(Rb_a.X, Rb_a.Y, Da.D.Bytes())
	if x2.Cmp(Rb.X) != 0 {
		fmt.Println("验证rb失败")
	}

	R, r1, s1, err := sm2.MutilSignA(Ra, *Rb, Da.D, msg, nil, rand.Reader)
	str := fmt.Sprintf("s1:%x", s1)
	conn.Write([]byte(str))
	fmt.Printf("RB:%x\n", Rb.X)

	n, err = conn.Read(buffer)
	MsgFromB := string(buffer[3:n])
	fmt.Printf("%x", MsgFromB)
	t1byte, _ := hex.DecodeString(MsgFromB)
	t1 := new(big.Int).SetBytes(t1byte)

	r, s, err := sm2.MutilSignA2(curve.Params().N, t1, r1)
	s.Mod(s, curve.Params().N)

	fmt.Printf("t1:%x\nr:%x\ns:%x\n", t1, r, s)

	Sign := sm2.RS2sign(r, s)

	ok := R.MVerify(msg, Sign)
	if err != nil {
		log.Println(err)
	}

	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}

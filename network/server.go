//Server.go
package main

import (
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

func main() {
	//服务端在本机8888端口建立tcp监听
	listener, err := net.Listen("tcp", "172.22.110.80:9090")
	ServerHandleError(err, "net.listen")
	for {
		//循环接入所有客户端得到专线连接
		conn, e := listener.Accept()
		fmt.Println("连接客户端")
		ServerHandleError(e, "listener.accept")
		//开辟独立协程与该客聊天
		go ChatWith(conn)
	}
}

func ServerHandleError(err error, when string) {
	if err != nil {
		fmt.Println(err, when)
		os.Exit(1)
	}
}

//在conn网络专线中与客户端对话
func ChatWith(conn net.Conn) {

	//创建消息缓冲区

	for {
		MulsignB(conn)

	}
	conn.Close()
	fmt.Printf("客户端断开连接", conn.RemoteAddr())

}

func MulsignB(conn net.Conn) {
	buffer := make([]byte, 1024)
	keyMap := Getkey()
	fmt.Println("keymap", keyMap)
	Db := new(sm2.PrivateKey)
	Puka := new(sm2.PublicKey)
	Db.Curve = sm2.P256Sm2()
	Db.D = new(big.Int).SetBytes(keyMap["db"])
	Db.X = new(big.Int).SetBytes(keyMap["pukb_x"])
	Db.Y = new(big.Int).SetBytes(keyMap["pukb_y"])
	Puka.X = new(big.Int).SetBytes(keyMap["puka_x"])
	Puka.Y = new(big.Int).SetBytes(keyMap["puka_y"])

	n, err := conn.Read(buffer)
	ServerHandleError(err, "conn.read buffer")

	//转化为字符串输出
	MsgFromA := string(buffer[0:n])
	fmt.Printf("收到消息", MsgFromA)

	recRa := new(RaData)
	json.Unmarshal([]byte(MsgFromA), &recRa) //json解析到结构体里面
	fmt.Println("recRa", recRa)

	Ra := new(sm2.PublicKey)
	Ra_b := new(sm2.PublicKey)
	Ra.X = recRa.Ra_x
	Ra.Y = recRa.Ra_y
	Ra_b.X = recRa.Rab_x
	Ra_b.Y = recRa.Rab_y

	Rb, Rb_a, err := sm2.GenerateRb(rand.Reader, Db, *Ra, *Ra_b, *Puka)
	if err != nil {
		log.Fatal("生成rb失败")

	}
	sendstr := new(RbData)
	sendstr.Rb_x = Rb.X
	sendstr.Rb_y = Rb.Y
	sendstr.Rba_x = Rb_a.X
	sendstr.Rba_y = Rb_a.Y
	buffer, err = json.Marshal(sendstr)

	conn.Write(buffer)

	n, err = conn.Read(buffer)
	MsgFromA = string(buffer[3:n])
	fmt.Printf("%x", MsgFromA)
	s1byte, _ := hex.DecodeString(MsgFromA)
	s1 := new(big.Int).SetBytes(s1byte)

	t1 := sm2.MutilSignB(s1, Db, Rb)

	str := fmt.Sprintf("t1:%x", t1)
	conn.Write([]byte(str))

}

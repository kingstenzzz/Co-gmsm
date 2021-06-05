package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func Getkey() map[string][]byte {
	userKey, err := os.OpenFile("network/user.txt", os.O_RDONLY, 0666)
	if err != nil {
		log.Println(err)
	}
	defer userKey.Close()

	map1 := make(map[string][]byte, 6)
	var num int8
	reader := bufio.NewReader(userKey)
	for {
		num++
		str, err := reader.ReadString('\n') //读到一个换行就结束
		line := strings.Split(str, ":")
		key := line[0]
		value := line[1]
		map1[key], _ = hex.DecodeString(value)
		if err == io.EOF { //io.EOF 表示文件的末尾
			break
		}
	}
	fmt.Println(map1)
	fmt.Println("文件读取结束...")
	return map1
}

//创建一个 json 构造体用来存储数据
type MyJsonPro struct {
	data interface{}
}

//json 构造体创建
func NewMyJsonPro(s string) *MyJsonPro {
	j := new(MyJsonPro)
	var r interface{}
	//解析对应的json 串 如果解析失败返回错误信息 否则 赋值给 r对应的数据
	err := json.Unmarshal([]byte(s), &r)

	if err != nil {
		return j
	}
	j.data = r
	return j
}

//获取 map 类型数据
func (this *MyJsonPro) GetMapData() map[string]interface{} {
	//使用断言的方式 获取MyJsonPro data的值取[map[string]interface{}类型数据
	if j, err := (this.data).(map[string]interface{}); err != false {
		return j
	}
	return nil
}

//获取对应 key 的值
func (this *MyJsonPro) GetValue(key string) interface{} {
	//获取对应的map数据
	d := this.GetMapData()
	//查看对应的 map数据中是否存在 值 如果存在进行赋值 否则 赋值为nil 值
	if s, err := d[key]; err != false {
		return s
	}
	return nil
}

//获取对应下标的值  需要传递 数组下标
func (this *MyJsonPro) GetIndex(index interface{}) interface{} {
	//使用断言的方式 获取MyJsonPro data的值取[]interface{}类型数据
	if d, err := (this.data).([]interface{}); err != false {
		num, int_err := index.(int)
		//如果断言方式取int类型的值失败
		if int_err != true {
			return nil
		}
		//防止数组越界 slice类型 下标从 0 开始如果小于0或导致报错
		if len(d)-1 < num || num < 0 {
			return nil
		}
		return d[num]
	}

	//使用断言的方式 获取MyJsonPro data的值取[map[string]interface{}类型数据
	if map_arr, set := (this.data).(map[string]interface{}); set != false {
		key, string_err := index.(string)
		//如果断言方式取stirng类型的值失败
		if string_err != true {
			return nil
		}
		if r, isset := map_arr[key]; isset != false {
			return r
		}

	}

	return nil
}

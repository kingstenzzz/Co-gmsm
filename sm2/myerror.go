package sm2

type GeneratePubError int

func (ki GeneratePubError) Error() string {
	return "生成公钥失败"
}

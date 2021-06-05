package sm2

func f() int {
	return z + y
}

func g() int {
	return y / 2
}

var (
	w       = x
	x, y, z = f(), 123, g()
)

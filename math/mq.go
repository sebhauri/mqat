package math

func MQ(F []Gf256, x []Gf256, m int) []Gf256 {
	fx := make([]Gf256, m)
	n := len(x)
	xij := quad(x)
	xijxi := append(xij, x...)
	for i := 0; i < int(m); i++ {
		fx[i] = mqi(F[i*(n*(n+1)/2+n):(i+1)*(n*(n+1)/2+n)], xijxi)
	}
	return fx
}

func G(F []Gf256, x []Gf256, y []Gf256, m int) []Gf256 {
	var n int
	if n = len(x); n != len(y) {
		return nil
	}
	gx := make([]Gf256, m)
	fx := MQ(F, x, m)
	fy := MQ(F, y, m)
	xy := make([]Gf256, n)
	for i := 0; i < n; i++ {
		xy[i] = x[i] + y[i]
	}
	fxy := MQ(F, xy, m)
	for i := 0; i < m; i++ {
		gxi := fxy[i] - fx[i] - fy[i]
		gx[i] = gxi
	}
	return gx
}

func mqi(Fi, xij []Gf256) Gf256 {
	flen := len(Fi)
	var fi Gf256 = 0
	for i := 0; i < flen; i++ {
		fi += Mul(Fi[i], xij[i])
	}
	return fi
}

func quad(x []Gf256) []Gf256 {
	n := len(x)
	filen := n * (n + 1) / 2
	xij := make([]Gf256, filen)
	k := 0
	for i := 0; i < n && k < filen; i++ {
		for j := i; j < n && k < filen; j++ {
			xijk := Mul(x[i], x[j])
			xij[k] = xijk
			k++
		}
	}
	return xij
}

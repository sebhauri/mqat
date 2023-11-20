package math

func MQ(F []Gf31s, x []uint8, m uint8) []uint8 {
	fx := make([]uint8, m)
	n := len(x)
	xij := quad(x)
	xijxi := append(xij, x...)
	for i := 0; i < int(m); i++ {
		fx[i] = mqi(F[i*(n*(n+1)/2+n):(i+1)*(n*(n+1)/2+n)], xijxi)
	}
	return fx
}

func G(F []Gf31s, x []uint8, y []uint8, m uint8) []uint8 {
	var n int
	if n = len(x); n != len(y) {
		return nil
	}
	gx := make([]uint8, m)
	fx := MQ(F, x, m)
	fy := MQ(F, y, m)
	xy := make([]uint8, n)
	for i := 0; i < n; i++ {
		xy[i] = Mod31(uint16(x[i] + y[i]))
	}
	fxy := MQ(F, xy, m)
	var i uint8
	for i = 0; i < m; i++ {
		gxi := int(fxy[i]) - int(fx[i]) - int(fy[i])
		gx[i] = Mod31(uint16((gxi >> 15) + (gxi & 0x7FFF)))
	}
	return gx
}

func mqi(Fi []Gf31s, xij []uint8) uint8 {
	flen := len(Fi)
	var fi int = 0
	for i := 0; i < flen; i++ {
		fi += (int(xij[i]) * int(Fi[i]))
	}
	return Mod31(uint16((fi >> 15) + (fi & 0x7FFF)))
}

func quad(x []uint8) []uint8 {
	n := len(x)
	filen := n * (n + 1) / 2
	xij := make([]uint8, filen)
	k := 0
	for i := 0; i < n && k < filen; i++ {
		for j := i; j < n && k < filen; j++ {
			ri := int(x[i]) * int(x[j])
			xij[k] = Mod31(uint16((ri >> 15) + (ri & 0x7FFF)))
			k++
		}
	}
	return xij
}

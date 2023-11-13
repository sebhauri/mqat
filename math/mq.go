package math

func MQ(F []Gf31s, x []Gf31, m uint8) []Gf31 {
	fx := make([]Gf31, m)
	n := len(x)
	xij := quad(x)
	for i := 0; i < int(m); i++ {
		fx[i] = mqi(F[i*(n*(n+1)/2+n):(i+1)*(n*(n+1)/2+n)], append(xij, x...))
	}
	return fx
}

func mqi(Fi []Gf31s, xij []Gf31) Gf31 {
	flen := len(Fi)
	var fi int = 0
	for i := 0; i < flen; i++ {
		fi += (int(xij[i]) * int(Fi[i]))
	}
	return Mod31(Gf31((fi >> 15) + (fi & 0x7FFF)))
}

func quad(x []Gf31) []Gf31 {
	n := len(x)
	filen := n * (n + 1) / 2
	xij := make([]Gf31, filen)
	k := 0
	for i := 0; i < n && k < filen; i++ {
		for j := i; j < n && k < filen; j++ {
			ri := int(x[i]) * int(x[j])
			xij[k] = Mod31(Gf31((ri >> 15) + (ri & 0x7FFF)))
			k++
		}
	}
	return xij
}

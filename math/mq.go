package math

func MQ(F []uint8, x []uint8, m int) []uint8 {
	fx := make([]uint8, m)
	n := len(x)
	xij := quad(x)
	for i := 0; i < m; i++ {
		fx[i] = mqi(F[Flen(i, n):Flen(i+1, n)], xij)
	}
	return fx
}

func MQUOV(P1i, P2i, P3i, x []uint8, m int) []uint8 {
	fx := make([]uint8, 0)
	n := len(x)

	vec := NewVector(x)

	lenP1 := (n - m) * (n - m + 1) / 2
	lenP2 := (n - m) * m
	lenP3 := m * (m + 1) / 2

	for k := 0; k < m; k++ {
		var acc uint8 = 0
		P1 := NewUpperTriangle(
			NewDenseMatrix(
				n-m, n-m,
				P1i[k*lenP1:(k+1)*lenP1],
			),
		)
		P2 := NewDenseMatrix(
			n-m, m, P2i[k*lenP2:(k+1)*lenP2],
		)
		P3 := NewUpperTriangle(
			NewDenseMatrix(
				m, m, P3i[k*lenP3:(k+1)*lenP3],
			),
		)
		for i := 0; i < n; i++ {
			for j := i; j < n; j++ {
				t := Mul(vec.At(i, 0), vec.At(j, 0))
				if j < n-m {
					acc ^= Mul(t, P1.At(i, j))
				} else {
					if i < n-m {
						acc ^= Mul(t, P2.At(i, j-n+m))
					} else {
						acc ^= Mul(t, P3.At(i-n+m, j-n+m))
					}
				}
			}
		}
		fx = append(fx, acc)
	}
	return fx
}

func G(F []uint8, x []uint8, y []uint8, m int) []uint8 {
	var n int
	if n = len(x); n != len(y) {
		return nil
	}
	gx := make([]uint8, m)
	fx := MQ(F, x, m)
	fy := MQ(F, y, m)
	xy := make([]uint8, n)
	for i := 0; i < n; i++ {
		xy[i] = x[i] ^ y[i]
	}
	fxy := MQ(F, xy, m)
	for i := 0; i < m; i++ {
		gxi := fxy[i] ^ fx[i] ^ fy[i]
		gx[i] = gxi
	}
	return gx
}

func Flen(m, n int) int {
	return m * n * (n + 1) / 2
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func mqi(Fi, xij []uint8) uint8 {
	flen := len(Fi)
	var fi uint8 = 0
	for i := 0; i < flen; i++ {
		fi ^= Mul(Fi[i], xij[i])
	}
	return fi
}

func quad(x []uint8) []uint8 {
	n := len(x)
	filen := n * (n + 1) / 2
	xij := make([]uint8, filen)
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

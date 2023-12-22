package math

func MQ(P1i, P2i, P3i, R, x []uint8, m, n int) []uint8 {
	x1 := x[:n]
	x2 := x[n:]

	Px1 := MQP(P1i, P2i, P3i, x1, m)
	Rx2 := MQR(R, x2, m)

	res := make([]uint8, m)
	for i := 0; i < m; i++ {
		res[i] = Px1[i] ^ Rx2[i]
	}
	return res
}

func MQR(R []uint8, x []uint8, m int) []uint8 {
	fx := make([]uint8, m)
	n := len(x)
	xij := quad(x)
	for i := 0; i < m; i++ {
		fx[i] = mqi(R[Flen(i, n):Flen(i+1, n)], xij)
	}
	return fx
}

func MQP(P1i, P2i, P3i, x []uint8, m int) []uint8 {
	fx := make([]uint8, m)
	n := len(x)

	vec := NewVector(x)

	lenP1 := (n - m) * (n - m + 1) / 2
	lenP2 := (n - m) * m
	lenP3 := m * (m + 1) / 2

	P1s := make([]UpperTriangle, 0)
	P2s := make([]*Dense, 0)
	P3s := make([]UpperTriangle, 0)
	for k := 0; k < m; k++ {
		P1s = append(P1s,
			NewUpperTriangle(
				NewDenseMatrix(
					n-m, n-m,
					P1i[k*lenP1:(k+1)*lenP1],
				),
			),
		)
		P2s = append(P2s,
			NewDenseMatrix(
				n-m, m, P2i[k*lenP2:(k+1)*lenP2],
			),
		)
		P3s = append(P3s,
			NewUpperTriangle(
				NewDenseMatrix(
					m, m, P3i[k*lenP3:(k+1)*lenP3],
				),
			),
		)
	}

	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			t := Mul(vec.At(i, 0), vec.At(j, 0))
			for k := 0; k < m; k++ {
				if j < n-m {
					fx[k] ^= Mul(t, P1s[k].At(i, j))
				} else {
					if i < n-m {
						fx[k] ^= Mul(t, P2s[k].At(i, j-n+m))
					} else {
						fx[k] ^= Mul(t, P3s[k].At(i-n+m, j-n+m))
					}
				}
			}
		}
	}

	// for k := 0; k < m; k++ {
	// 	var acc uint8 = 0
	// 	P1 := NewUpperTriangle(
	// 		NewDenseMatrix(
	// 			n-m, n-m,
	// 			P1i[k*lenP1:(k+1)*lenP1],
	// 		),
	// 	)
	// 	P2 := NewDenseMatrix(
	// 		n-m, m, P2i[k*lenP2:(k+1)*lenP2],
	// 	)
	// 	P3 := NewUpperTriangle(
	// 		NewDenseMatrix(
	// 			m, m, P3i[k*lenP3:(k+1)*lenP3],
	// 		),
	// 	)
	// 	for i := 0; i < n; i++ {
	// 		for j := i; j < n; j++ {
	// 			t := Mul(vec.At(i, 0), vec.At(j, 0))
	// 			if j < n-m {
	// 				acc ^= Mul(t, P1.At(i, j))
	// 			} else {
	// 				if i < n-m {
	// 					acc ^= Mul(t, P2.At(i, j-n+m))
	// 				} else {
	// 					acc ^= Mul(t, P3.At(i-n+m, j-n+m))
	// 				}
	// 			}
	// 		}
	// 	}
	// 	fx = append(fx, acc)
	// }
	return fx
}

func G(P1i, P2i, P3i, R, x, y []uint8, m, n int) []uint8 {
	if len(x) != len(y) {
		return nil
	}
	gx := make([]uint8, m)
	fx := MQ(P1i, P2i, P3i, R, x, m, n)
	fy := MQ(P1i, P2i, P3i, R, y, m, n)
	xy := make([]uint8, m+n)
	for i := 0; i < m+n; i++ {
		xy[i] = x[i] ^ y[i]
	}
	fxy := MQ(P1i, P2i, P3i, R, xy, m, n)
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

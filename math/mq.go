package math

func MQ(P1i, P2i, P3i, R []Matrix, x Vector, m, n int) Vector {
	x1 := x[:n]
	x2 := x[n:]

	Px1 := MQP(P1i, P2i, P3i, x1, m)
	Rx2 := MQR(R, x2, m)

	return AddVec(Px1, Rx2)
}

func MQR(R []Matrix, x Vector, m int) Vector {
	n := x.Len()
	px := NewDenseVector(m, nil)

	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			t := Mul(x.AtVec(i), x.AtVec(j))
			for k := 0; k < m; k++ {
				px.SetVec(k, px.AtVec(k)^Mul(t, R[k].At(i, j)))
			}
		}
	}

	return px
}

func MQP(P1i, P2i, P3i []Matrix, x Vector, m int) Vector {
	n := x.Len()
	px := NewDenseVector(m, nil)

	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			t := Mul(x.AtVec(i), x.AtVec(j))
			for k := 0; k < m; k++ {
				if j < n-m {
					px.SetVec(k, px.AtVec(k)^Mul(t, P1i[k].At(i, j)))
				} else {
					if i < n-m {
						px.SetVec(k, px.AtVec(k)^Mul(t, P2i[k].At(i, j-n+m)))
					} else {
						px.SetVec(k, px.AtVec(k)^Mul(t, P3i[k].At(i-n+m, j-n+m)))
					}
				}
			}
		}
	}

	return px
}

func G(P1i, P2i, P3i, R []Matrix, x, y Vector, m, n int) Vector {
	xy := AddVec(x, y)
	if xy == nil {
		return nil
	}

	fx := MQ(P1i, P2i, P3i, R, x, m, n)
	fy := MQ(P1i, P2i, P3i, R, y, m, n)
	fxy := MQ(P1i, P2i, P3i, R, xy, m, n)

	return AddVec(fxy, AddVec(fx, fy))
}

func Flen(m, n int) int {
	return m * n * (n + 1) / 2
}

package math

type Matrix interface {
	At(i, j int) Gf256
	Dims() (int, int)
	Set(i, j int, v Gf256)
}

type Vector interface {
	Matrix
	AtVec(i int) Gf256
	Len() int
	SetVec(i int, v Gf256)
}

////////////////////////////////////////////////////////////////////////////////

type DenseM struct {
	data       []Gf256
	rows, cols int
}

func NewDenseMatrix(rows, cols int, data []Gf256) *DenseM {
	if data == nil {
		data = make([]Gf256, rows*cols)
	}
	return &DenseM{
		data: data,
		rows: rows,
		cols: cols,
	}
}

func (d *DenseM) At(i, j int) Gf256 {
	return d.data[i*d.cols+j]
}

func (d *DenseM) Dims() (int, int) {
	return d.rows, d.cols
}

func (d *DenseM) Set(i, j int, v Gf256) {
	d.data[i*d.cols+j] = v
}

type DenseV struct {
	data []Gf256
}

func NewDenseVector(data []Gf256) *DenseV {
	if data == nil {
		data = make([]Gf256, 0)
	}
	return &DenseV{data: data}
}

func (v *DenseV) At(i, j int) Gf256 {
	return v.AtVec(i)
}

func (v *DenseV) AtVec(i int) Gf256 {
	return v.data[i]
}

func (v *DenseV) Dims() (int, int) {
	return v.Len(), 1
}

func (v *DenseV) Len() int {
	return len(v.data)
}

func (v *DenseV) Set(i, j int, val Gf256) {
	if j != 0 {
		panic("")
	}
	v.SetVec(i, val)
}

func (v *DenseV) SetVec(i int, val Gf256) {
	v.data[i] = val
}

////////////////////////////////////////////////////////////////////////////////

type Transpose struct {
	m Matrix
}

func T(M Matrix) Matrix {
	if t, ok := M.(Transpose); ok {
		return t.m
	}
	return Transpose{m: M}
}

func (t Transpose) At(i, j int) Gf256 {
	return t.m.At(j, i)
}

func (t Transpose) Dims() (int, int) {
	r, c := t.m.Dims()
	return c, r
}

func (t Transpose) Set(i, j int, v Gf256) {
	t.m.Set(j, i, v)
}

////////////////////////////////////////////////////////////////////////////////

type UpperTriangle struct {
	m Matrix
}

func NewUpperTriangle(M Matrix) UpperTriangle {
	return UpperTriangle{m: M}
}

func (u UpperTriangle) At(i, j int) Gf256 {
	if j < i {
		return 0
	}
	return u.m.At(i, j-i*(i-1)/2-i)
}

func (u UpperTriangle) Dims() (int, int) {
	return u.m.Dims()
}

func (u UpperTriangle) Set(i, j int, v Gf256) {
	if i < j {
		return
	}
	u.m.Set(i, j-i*(i-1)/2-i, v)
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func MulMat(A, B Matrix) *DenseM {
	rowsA, colsA := A.Dims()
	rowsB, colsB := B.Dims()
	if colsA != rowsB {
		return nil
	}

	res := NewDenseMatrix(rowsA, colsB, nil)
	for i := 0; i < rowsA; i++ {
		for j := 0; j < colsB; j++ {
			var tmp Gf256 = 0
			for k := 0; k < colsA; k++ {
				tmp ^= Mul(A.At(i, k), B.At(k, j))
			}
			res.Set(i, j, tmp)
		}
	}

	return res
}

func MulVec(A Matrix, b Vector) *DenseV {
	r, c := A.Dims()
	l := b.Len()
	if c != l {
		return nil
	}
	_, ok := A.(UpperTriangle)

	res := NewDenseVector(nil)
	for i := 0; i < r; i++ {
		var tmp Gf256 = 0
		j := 0
		if ok {
			j = i
		}
		for ; j < l; j++ {
			tmp ^= Mul(A.At(i, j), b.AtVec(j))
		}
		res.SetVec(i, tmp)
	}
	return res
}

func AddMat(A, B Matrix) *DenseM {
	rowsA, colsA := A.Dims()
	rowsB, colsB := B.Dims()
	if rowsA != rowsB || colsA != colsB {
		return nil
	}

	res := NewDenseMatrix(rowsA, colsB, nil)
	for i := 0; i < rowsA; i++ {
		for j := 0; j < colsB; j++ {
			res.Set(i, j, A.At(i, j)^B.At(i, j))
		}
	}

	return res
}

func ScaleMat(M Matrix, v Gf256) *DenseM {
	rows, cols := M.Dims()
	res := NewDenseMatrix(rows, cols, nil)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			val := Mul(v, M.At(i, j))
			res.Set(i, j, val)
		}
	}
	return res
}

func Solve(A Matrix, b Vector) *DenseV {
	r, c := A.Dims()
	l, _ := b.Dims()
	if r != c || r != l {
		return nil
	}

	Ab := make([]Gf256, 0)
	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			Ab = append(Ab, A.At(i, j))
		}
		Ab = append(Ab, b.AtVec(i))
	}
	if len(Ab) != (l+1)*l {
		return nil
	}

	AbMat := NewDenseMatrix(l, l+1, Ab)
	for i := 0; i < l; i++ {
		for j := i + 1; j < l; j++ {
			if AbMat.At(i, i) == 0 {
				for k := i; k < l+1; k++ {
					AbMat.Set(i, k, AbMat.At(i, k)^AbMat.At(j, k))
				}
			}
		}
		if AbMat.At(i, i) == 0 {
			return nil
		}
		pi := Inv(AbMat.At(i, i))
		for k := i; k < l+1; k++ {
			AbMat.Set(i, k, Mul(pi, AbMat.At(i, k)))
		}
		for j := i + 1; j < l; j++ {
			aji := AbMat.At(j, i)
			for k := i; k < l+1; k++ {
				AbMat.Set(j, k, AbMat.At(j, k)^Mul(aji, AbMat.At(i, k)))
			}
		}
	}

	for i := l - 1; i > 0; i-- {
		aim := AbMat.At(i, l)
		for j := 0; j < i; j++ {
			AbMat.Set(j, l, AbMat.At(j, l)^Mul(AbMat.At(j, i), aim))
		}
	}

	res := make([]Gf256, 0)
	r, c = AbMat.Dims()
	for i := 0; i < r; i++ {
		res = append(res, AbMat.At(i, c-1))
	}
	return NewDenseVector(res)
}

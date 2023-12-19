package math

type Matrix interface {
	At(i, j int) uint8
	Dims() (rows, cols int)
	Set(i, j int, v uint8)
}

////////////////////////////////////////////////////////////////////////////////

type Dense struct {
	Data       []uint8
	rows, cols int
}

func NewDenseMatrix(rows, cols int, data []uint8) *Dense {
	if data == nil {
		data = make([]uint8, rows*cols)
	}
	return &Dense{
		Data: data,
		rows: rows,
		cols: cols,
	}
}

func (d *Dense) At(i, j int) uint8 {
	return d.Data[i*d.cols+j]
}

func (d *Dense) Dims() (int, int) {
	return d.rows, d.cols
}

func (d *Dense) Set(i, j int, v uint8) {
	d.Data[i*d.cols+j] = v
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

func (t Transpose) At(i, j int) uint8 {
	return t.m.At(j, i)
}

func (t Transpose) Dims() (int, int) {
	r, c := t.m.Dims()
	return c, r
}

func (t Transpose) Set(i, j int, v uint8) {
	t.m.Set(j, i, v)
}

////////////////////////////////////////////////////////////////////////////////

type UpperTriangle struct {
	m Matrix
}

func NewUpperTriangle(M Matrix) UpperTriangle {
	return UpperTriangle{m: M}
}

func (u UpperTriangle) At(i, j int) uint8 {
	if i < j {
		return 0
	}
	return u.m.At(i, j-i*(i-1)/2-i)
}

func (u UpperTriangle) Dims() (int, int) {
	return u.m.Dims()
}

func (u UpperTriangle) Set(i, j int, v uint8) {
	if i < j {
		return
	}
	u.m.Set(i, j-i*(i-1)/2-i, v)
}

////////////////////////////////////////////////////////////////////////////////

type Vector struct {
	Matrix
	Data []uint8
}

func NewVector(data []uint8) Vector {
	if data == nil {
		data = make([]uint8, 0)
	}
	return Vector{Data: data}
}

func (v Vector) At(i, j int) uint8 {
	if j != 0 {
		panic("")
	}
	return v.Data[i]
}

func (v Vector) Dims() (int, int) {
	return len(v.Data), 1
}

func (v Vector) Set(i, j int, val uint8) {
	if j != 0 {
		panic("")
	}
	v.Data[i] = val
}

////////////////////////////////////////////////////////////////////////////////

func MulMat(A, B Matrix) *Dense {
	rowsA, colsA := A.Dims()
	rowsB, colsB := B.Dims()
	if colsA != rowsB {
		return nil
	}

	res := NewDenseMatrix(rowsA, colsB, nil)
	for i := 0; i < rowsA; i++ {
		for j := 0; j < colsB; j++ {
			var tmp uint8 = 0
			for k := 0; k < colsA; k++ {
				tmp ^= Mul(A.At(i, k), B.At(k, j))
			}
			res.Set(i, j, tmp)
		}
	}

	return res
}

func AddMat(A, B Matrix) *Dense {
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

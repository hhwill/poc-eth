package curve25519

/* p[m..n+m-1] = q[m..n+m-1] + z * x */
/* n is the size of x */
/* n+m is the size of p and q */
func mulaSmall(p []byte, q []byte, m int, x []byte, n int, z int) int {
	v := 0
	for i := 0; i < n; i++ {
		v += int(q[i+m]&0xFF) + z*int(x[i]&0xFF)
		p[i+m] = byte(v)
		v >>= 8
	}
	return v
}

/* p += x * y * z  where z is a small integer
 * x is size 32, y is size t, p is size 32+t
 * y is allowed to overlap with p+32 if you don't care about the upper half  */
func mula32(p []byte, x []byte, y []byte, t int, z int) int {
	const n = 31
	var w, i int
	for ; i < t; i++ {
		zy := z * int(y[i]&0xFF)
		w += mulaSmall(p, p, i, x, n, zy) + int(p[i+n]&0xFF) + zy*int(x[n]&0xFF)
		p[i+n] = byte(w)
		w >>= 8
	}
	p[i+n] = byte(w + int(p[i+n]&0xFF))
	return w >> 8
}

/* divide r (size n) by d (size t), returning quotient q and remainder r
 * quotient is size n-t+1, remainder is size t
 * requires t > 0 && d[t-1] != 0
 * requires that r[-1] and d[-1] are valid memory locations
 * q may overlap with r+t */
func divmod(q []byte, r []byte, n int, d []byte, t int) {
	rn := 0
	dt := int(d[t-1]&0xFF) << 8
	if t > 1 {
		dt |= int(d[t-2] & 0xFF)
	}
	for n >= t {
		n--
		z := (rn << 16) | (int(r[n]&0xFF) << 8)
		if n > 0 {
			z |= int(r[n-1] & 0xFF)
		}
		z /= dt
		rn += mulaSmall(r, r, n-t+1, d, t, -z)
		q[n-t+1] = byte((z + rn) & 0xFF) /* rn is 0 or -1 (underflow) */
		mulaSmall(r, r, n-t+1, d, t, -rn)
		rn = int(r[n] & 0xFF)
		r[n] = 0
	}
	r[t-1] = byte(rn)
}

func numsize(x []byte, n int) int {
	for n != 0 && x[n-1] == 0 {
		n--
	}
	return n
}

/* Returns x if a contains the gcd, y if b.
 * Also, the returned buffer contains the inverse of a mod b,
 * as 32-byte signed.
 * x and y must have 64 bytes space for temporary use.
 * requires that a[-1] and b[-1] are valid memory locations  */
func egcd32(x []byte, y []byte, a []byte, b []byte) []byte {
	for i := 0; i < 32; i++ {
		x[i] = 0
		y[i] = 0
	}
	x[0] = 1

	an := numsize(a, 32)
	if an == 0 {
		return y /* division by zero */
	}
	bn := 32

	temp := make([]byte, 32)
	for {
		qn := bn - an + 1
		divmod(temp, b, bn, a, an)
		bn = numsize(b, bn)
		if bn == 0 {
			return x
		}
		mula32(y, x, temp, qn, -1)
		qn = an - bn + 1
		divmod(temp, a, an, b, bn)
		an = numsize(a, an)
		if an == 0 {
			return y
		}
		mula32(x, y, temp, qn, -1)
	}
}

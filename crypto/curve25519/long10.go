package curve25519

const p25 = 33554431 /* (1 << 25) - 1 */
const p26 = 67108863 /* (1 << 26) - 1 */

/* constants 2Gy and 1/(2Gy) */
var base2y = &long10{39999547, 18689728, 59995525, 1648697, 57546132, 24010086, 19059592, 5425144, 63499247, 16420658}

var baseR2y = &long10{5744, 8160848, 4790893, 13779497, 35730846, 12541209, 49101323, 30047407, 40071253, 6226132}

type long10 [10]int64

/* Convert to internal format from little-endian byte format */
func (x *long10) unpack(m []byte) {
	x[0] = int64(m[0]&0xFF) | int64(m[1]&0xFF)<<8 | int64(m[2]&0xFF)<<16 | (int64(m[3]&0xFF)&3)<<24
	x[1] = (int64(m[3]&0xFF)&^3)>>2 | int64(m[4]&0xFF)<<6 | int64(m[5]&0xFF)<<14 | (int64(m[6]&0xFF)&7)<<22
	x[2] = (int64(m[6]&0xFF)&^7)>>3 | int64(m[7]&0xFF)<<5 | int64(m[8]&0xFF)<<13 | (int64(m[9]&0xFF)&31)<<21
	x[3] = (int64(m[9]&0xFF)&^31)>>5 | int64(m[10]&0xFF)<<3 | int64(m[11]&0xFF)<<11 | (int64(m[12]&0xFF)&63)<<19
	x[4] = (int64(m[12]&0xFF)&^63)>>6 | int64(m[13]&0xFF)<<2 | int64(m[14]&0xFF)<<10 | int64(m[15]&0xFF)<<18
	x[5] = int64(m[16]&0xFF) | int64(m[17]&0xFF)<<8 | int64(m[18]&0xFF)<<16 | (int64(m[19]&0xFF)&1)<<24
	x[6] = (int64(m[19]&0xFF)&^1)>>1 | int64(m[20]&0xFF)<<7 | int64(m[21]&0xFF)<<15 | (int64(m[22]&0xFF)&7)<<23
	x[7] = (int64(m[22]&0xFF)&^7)>>3 | int64(m[23]&0xFF)<<5 | int64(m[24]&0xFF)<<13 | (int64(m[25]&0xFF)&15)<<21
	x[8] = (int64(m[25]&0xFF)&^15)>>4 | int64(m[26]&0xFF)<<4 | int64(m[27]&0xFF)<<12 | (int64(m[28]&0xFF)&63)<<20
	x[9] = (int64(m[28]&0xFF)&^63)>>6 | int64(m[29]&0xFF)<<2 | int64(m[30]&0xFF)<<10 | int64(m[31]&0xFF)<<18
}

/* Check if reduced-form input >= 2^255-19 */
func (x *long10) isOverflow() bool {
	return ((x[0] > p26-19) && ((x[1] & x[3] & x[5] & x[7] & x[9]) == p25) && ((x[2] & x[4] & x[6] & x[8]) == p26)) || (x[9] > p25)
}

/* Convert from internal format to little-endian byte format.  The
 * number must be in a reduced form which is output by the following ops:
 *     unpack, mul, sqr
 *     set --  if input in range 0 .. P25
 * If you're unsure if the number is reduced, first multiply it by 1.  */
func (x *long10) pack(m []byte) []byte {

	var ld int64
	if x.isOverflow() {
		ld = 1
	} else {
		ld = 0
	}
	if x[9] < 0 {
		ld -= 1
	}
	ud := ld * -(p25 + 1)
	ld *= 19

	if m == nil {
		m = make([]byte, 32)
	}
	t := ld + x[0] + (x[1] << 26)

	m[0] = byte(t)
	m[1] = byte(t >> 8)
	m[2] = byte(t >> 16)
	m[3] = byte(t >> 24)
	t = (t >> 32) + (x[2] << 19)

	m[4] = byte(t)
	m[5] = byte(t >> 8)
	m[6] = byte(t >> 16)
	m[7] = byte(t >> 24)
	t = (t >> 32) + (x[3] << 13)

	m[8] = byte(t)
	m[9] = byte(t >> 8)
	m[10] = byte(t >> 16)
	m[11] = byte(t >> 24)
	t = (t >> 32) + (x[4] << 6)

	m[12] = byte(t)
	m[13] = byte(t >> 8)
	m[14] = byte(t >> 16)
	m[15] = byte(t >> 24)
	t = (t >> 32) + x[5] + (x[6] << 25)

	m[16] = byte(t)
	m[17] = byte(t >> 8)
	m[18] = byte(t >> 16)
	m[19] = byte(t >> 24)
	t = (t >> 32) + (x[7] << 19)

	m[20] = byte(t)
	m[21] = byte(t >> 8)
	m[22] = byte(t >> 16)
	m[23] = byte(t >> 24)
	t = (t >> 32) + (x[8] << 12)

	m[24] = byte(t)
	m[25] = byte(t >> 8)
	m[26] = byte(t >> 16)
	m[27] = byte(t >> 24)
	t = (t >> 32) + ((x[9] + ud) << 6)

	m[28] = byte(t)
	m[29] = byte(t >> 8)
	m[30] = byte(t >> 16)
	m[31] = byte(t >> 24)
	return m
}

/* Copy a number */
func (out *long10) cpy(in *long10) {
	copy(out[:], in[:])
}

/* Set a number to value, which must be in range -185861411 .. 185861411 */
func (out *long10) set(in int) {
	out[0] = int64(in)
	for i := 1; i < len(out); i++ {
		out[i] = 0
	}
}

/* Add/subtract two numbers.  The inputs must be in reduced form, and the
 * output isn't, so to do another addition or subtraction on the output,
 * first multiply it by one to reduce it. */
func (xy *long10) add(x, y *long10) {
	for i := 0; i < len(xy); i++ {
		xy[i] = x[i] + y[i]
	}
}

func (xy *long10) sub(x, y *long10) {
	for i := 0; i < len(xy); i++ {
		xy[i] = x[i] - y[i]
	}
}

/* Multiply a number by a small integer in range -185861411 .. 185861411.
 * The output is in reduced form, the input x need not be.  x and xy may point
 * to the same buffer. */
func (xy *long10) mulSmall(x *long10, y int64) {
	t := x[8] * y
	xy[8] = t & ((1 << 26) - 1)
	t = (t >> 26) + (x[9] * y)
	xy[9] = t & ((1 << 25) - 1)
	t = 19*(t>>25) + (x[0] * y)
	xy[0] = t & ((1 << 26) - 1)
	t = (t >> 26) + (x[1] * y)
	xy[1] = t & ((1 << 25) - 1)
	t = (t >> 25) + (x[2] * y)
	xy[2] = t & ((1 << 26) - 1)
	t = (t >> 26) + (x[3] * y)
	xy[3] = t & ((1 << 25) - 1)
	t = (t >> 25) + (x[4] * y)
	xy[4] = t & ((1 << 26) - 1)
	t = (t >> 26) + (x[5] * y)
	xy[5] = t & ((1 << 25) - 1)
	t = (t >> 25) + (x[6] * y)
	xy[6] = t & ((1 << 26) - 1)
	t = (t >> 26) + (x[7] * y)
	xy[7] = t & ((1 << 25) - 1)
	t = (t >> 25) + xy[8]
	xy[8] = t & ((1 << 26) - 1)
	xy[9] += t >> 26
}

/* Multiply two numbers.  The output is in reduced form, the inputs need not
 * be. */
func (xy *long10) mul(x, y *long10) {
	/* sahn0:
	 * Using local variables to avoid class access.
	 * This seem to improve performance a bit...
	 */
	t := x[0]*y[8] + x[2]*y[6] + x[4]*y[4] + x[6]*y[2] + x[8]*y[0] + 2*((x[1]*y[7])+(x[3]*y[5])+(x[5]*y[3])+(x[7]*y[1])) + 38*(x[9]*y[9])
	xy[8] = t & ((1 << 26) - 1)
	t = (t >> 26) + x[0]*y[9] + x[1]*y[8] + x[2]*y[7] + x[3]*y[6] + x[4]*y[5] + x[5]*y[4] + x[6]*y[3] + x[7]*y[2] + x[8]*y[1] + x[9]*y[0]
	xy[9] = t & ((1 << 25) - 1)
	t = x[0]*y[0] + 19*((t>>25)+(x[2]*y[8])+(x[4]*y[6])+(x[6]*y[4])+(x[8]*y[2])) + 38*((x[1]*y[9])+(x[3]*y[7])+(x[5]*y[5])+(x[7]*y[3])+(x[9]*y[1]))
	xy[0] = t & ((1 << 26) - 1)
	t = (t >> 26) + x[0]*y[1] + x[1]*y[0] + 19*((x[2]*y[9])+(x[3]*y[8])+(x[4]*y[7])+(x[5]*y[6])+(x[6]*y[5])+(x[7]*y[4])+(x[8]*y[3])+(x[9]*y[2]))
	xy[1] = t & ((1 << 25) - 1)
	t = (t >> 25) + x[0]*y[2] + x[2]*y[0] + 19*((x[4]*y[8])+(x[6]*y[6])+(x[8]*y[4])) + 2*(x[1]*y[1]) + 38*((x[3]*y[9])+(x[5]*y[7])+(x[7]*y[5])+(x[9]*y[3]))
	xy[2] = t & ((1 << 26) - 1)
	t = (t >> 26) + x[0]*y[3] + x[1]*y[2] + x[2]*y[1] + x[3]*y[0] + 19*((x[4]*y[9])+(x[5]*y[8])+(x[6]*y[7])+(x[7]*y[6])+(x[8]*y[5])+(x[9]*y[4]))
	xy[3] = t & ((1 << 25) - 1)
	t = (t >> 25) + x[0]*y[4] + x[2]*y[2] + x[4]*y[0] + 19*((x[6]*y[8])+(x[8]*y[6])) + 2*((x[1]*y[3])+(x[3]*y[1])) + 38*((x[5]*y[9])+(x[7]*y[7])+(x[9]*y[5]))
	xy[4] = t & ((1 << 26) - 1)
	t = (t >> 26) + x[0]*y[5] + x[1]*y[4] + x[2]*y[3] + x[3]*y[2] + x[4]*y[1] + x[5]*y[0] + 19*((x[6]*y[9])+(x[7]*y[8])+(x[8]*y[7])+(x[9]*y[6]))
	xy[5] = t & ((1 << 25) - 1)
	t = (t >> 25) + x[0]*y[6] + x[2]*y[4] + x[4]*y[2] + x[6]*y[0] + 19*(x[8]*y[8]) + 2*((x[1]*y[5])+(x[3]*y[3])+(x[5]*y[1])) + 38*((x[7]*y[9])+(x[9]*y[7]))
	xy[6] = t & ((1 << 26) - 1)
	t = (t >> 26) + x[0]*y[7] + x[1]*y[6] + x[2]*y[5] + x[3]*y[4] + x[4]*y[3] + x[5]*y[2] + x[6]*y[1] + x[7]*y[0] + 19*((x[8]*y[9])+(x[9]*y[8]))
	xy[7] = t & ((1 << 25) - 1)
	t = (t >> 25) + xy[8]
	xy[8] = t & ((1 << 26) - 1)
	xy[9] += t >> 26
}

/* Square a number.  Optimization of  mul25519(x2, x, x)  */
func (x2 *long10) sqr(x *long10) {
	t := x[4]*x[4] + 2*((x[0]*x[8])+(x[2]*x[6])) + 38*(x[9]*x[9]) + 4*((x[1]*x[7])+(x[3]*x[5]))
	x2[8] = t & ((1 << 26) - 1)
	t = (t >> 26) + 2*((x[0]*x[9])+(x[1]*x[8])+(x[2]*x[7])+(x[3]*x[6])+(x[4]*x[5]))
	x2[9] = t & ((1 << 25) - 1)
	t = 19*(t>>25) + x[0]*x[0] + 38*((x[2]*x[8])+(x[4]*x[6])+(x[5]*x[5])) + 76*((x[1]*x[9])+(x[3]*x[7]))
	x2[0] = t & ((1 << 26) - 1)
	t = (t >> 26) + 2*(x[0]*x[1]) + 38*((x[2]*x[9])+(x[3]*x[8])+(x[4]*x[7])+(x[5]*x[6]))
	x2[1] = t & ((1 << 25) - 1)
	t = (t >> 25) + 19*(x[6]*x[6]) + 2*((x[0]*x[2])+(x[1]*x[1])) + 38*(x[4]*x[8]) + 76*((x[3]*x[9])+(x[5]*x[7]))
	x2[2] = t & ((1 << 26) - 1)
	t = (t >> 26) + 2*((x[0]*x[3])+(x[1]*x[2])) + 38*((x[4]*x[9])+(x[5]*x[8])+(x[6]*x[7]))
	x2[3] = t & ((1 << 25) - 1)
	t = (t >> 25) + x[2]*x[2] + 2*(x[0]*x[4]) + 38*((x[6]*x[8])+(x[7]*x[7])) + 4*(x[1]*x[3]) + 76*(x[5]*x[9])
	x2[4] = t & ((1 << 26) - 1)
	t = (t >> 26) + 2*((x[0]*x[5])+(x[1]*x[4])+(x[2]*x[3])) + 38*((x[6]*x[9])+(x[7]*x[8]))
	x2[5] = t & ((1 << 25) - 1)
	t = (t >> 25) + 19*(x[8]*x[8]) + 2*((x[0]*x[6])+(x[2]*x[4])+(x[3]*x[3])) + 4*(x[1]*x[5]) + 76*(x[7]*x[9])
	x2[6] = t & ((1 << 26) - 1)
	t = (t >> 26) + 2*((x[0]*x[7])+(x[1]*x[6])+(x[2]*x[5])+(x[3]*x[4])) + 38*(x[8]*x[9])
	x2[7] = t & ((1 << 25) - 1)
	t = (t >> 25) + x2[8]
	x2[8] = t & ((1 << 26) - 1)
	x2[9] += t >> 26
}

/* Calculates a reciprocal.  The output is in reduced form, the inputs need not
 * be.  Simply calculates  y = x^(p-2)  so it's not too fast. */
/* When sqrtAssist is true, it instead calculates y = x^((p-5)/8) */
func (y *long10) recip(x *long10, sqrtAssist bool) {
	t0 := new(long10)
	t1 := new(long10)
	t2 := new(long10)
	t3 := new(long10)
	t4 := new(long10)

	/* the chain for x^(2^255-21) is straight from djb's implementation */
	t1.sqr(x)      /*  2 == 2 * 1  */
	t2.sqr(t1)     /*  4 == 2 * 2  */
	t0.sqr(t2)     /*  8 == 2 * 4  */
	t2.mul(t0, x)  /*  9 == 8 + 1  */
	t0.mul(t2, t1) /* 11 == 9 + 2  */
	t1.sqr(t0)     /* 22 == 2 * 11 */
	t3.mul(t1, t2) /* 31 == 22 + 9 */
	/*             == 2^5   - 2^0  */
	t1.sqr(t3)     /* 2^6   - 2^1  */
	t2.sqr(t1)     /* 2^7   - 2^2  */
	t1.sqr(t2)     /* 2^8   - 2^3  */
	t2.sqr(t1)     /* 2^9   - 2^4  */
	t1.sqr(t2)     /* 2^10  - 2^5  */
	t2.mul(t1, t3) /* 2^10  - 2^0  */
	t1.sqr(t2)     /* 2^11  - 2^1  */
	t3.sqr(t1)     /* 2^12  - 2^2  */
	for i := 1; i < 5; i++ { /* t3 */
		t1.sqr(t3)
		t3.sqr(t1)
	}              /* 2^20  - 2^10 */
	t1.mul(t3, t2) /* 2^20  - 2^0  */
	t3.sqr(t1)     /* 2^21  - 2^1  */
	t4.sqr(t3)     /* 2^22  - 2^2  */
	for i := 1; i < 10; i++ { /* t4 */
		t3.sqr(t4)
		t4.sqr(t3)
	}              /* 2^40  - 2^20 */
	t3.mul(t4, t1) /* 2^40  - 2^0  */
	for i := 0; i < 5; i++ { /* t3 */
		t1.sqr(t3)
		t3.sqr(t1)
	}              /* 2^50  - 2^10 */
	t1.mul(t3, t2) /* 2^50  - 2^0  */
	t2.sqr(t1)     /* 2^51  - 2^1  */
	t3.sqr(t2)     /* 2^52  - 2^2  */
	for i := 1; i < 25; i++ { /* t3 */
		t2.sqr(t3)
		t3.sqr(t2)
	}              /* 2^100 - 2^50 */
	t2.mul(t3, t1) /* 2^100 - 2^0  */
	t3.sqr(t2)     /* 2^101 - 2^1  */
	t4.sqr(t3)     /* 2^102 - 2^2  */
	for i := 1; i < 50; i++ { /* t4 */
		t3.sqr(t4)
		t4.sqr(t3)
	}              /* 2^200 - 2^100 */
	t3.mul(t4, t2) /* 2^200 - 2^0  */
	for i := 0; i < 25; i++ { /* t3 */
		t4.sqr(t3)
		t3.sqr(t4)
	}              /* 2^250 - 2^50 */
	t2.mul(t3, t1) /* 2^250 - 2^0  */
	t1.sqr(t2)     /* 2^251 - 2^1  */
	t2.sqr(t1)     /* 2^252 - 2^2  */
	if sqrtAssist {
		y.mul(x, t2) /* 2^252 - 3 */
	} else {
		t1.sqr(t2)    /* 2^253 - 2^3  */
		t2.sqr(t1)    /* 2^254 - 2^4  */
		t1.sqr(t2)    /* 2^255 - 2^5  */
		y.mul(t1, t0) /* 2^255 - 21   */
	}
}

/* checks if x is "negative", requires reduced input */
func (x *long10) isNegative() bool {
	tmp := int64(0)
	if x.isOverflow() || x[9] < 0 {
		tmp = 1
	}
	tmp = tmp ^ (x[0] & 1)
	return tmp != 0
}

/* a square root */
func (x *long10) sqrt(u *long10) {
	v := new(long10)
	t1 := new(long10)
	t2 := new(long10)
	t1.add(u, u)      /* t1 = 2u    */
	v.recip(t1, true) /* v = (2u)^((p-5)/8) */
	x.sqr(v)          /* x = v^2    */
	t2.mul(t1, x)     /* t2 = 2uv^2   */
	t2[0]--           /* t2 = 2uv^2-1   */
	t1.mul(v, t2)     /* t1 = v(2uv^2-1)  */
	x.mul(u, t1)      /* x = uv(2uv^2-1)  */
}

/* t1 = ax + az
 * t2 = ax - az  */
func montPrep(t1, t2, ax, az *long10) {
	t1.add(ax, az)
	t2.sub(ax, az)
}

/* A = P + Q   where
 *  X(A) = ax/az
 *  X(P) = (t1+t2)/(t1-t2)
 *  X(Q) = (t3+t4)/(t3-t4)
 *  X(P-Q) = dx
 * clobbers t1 and t2, preserves t3 and t4  */
func montAdd(t1, t2, t3, t4, ax, az, dx *long10) {
	ax.mul(t2, t3)
	az.mul(t1, t4)
	t1.add(ax, az)
	t2.sub(ax, az)
	ax.sqr(t1)
	t1.sqr(t2)
	az.mul(t1, dx)
}

/* B = 2 * Q   where
 *  X(B) = bx/bz
 *  X(Q) = (t3+t4)/(t3-t4)
 * clobbers t1 and t2, preserves t3 and t4  */
func montDbl(t1, t2, t3, t4, bx, bz *long10) {
	t1.sqr(t3)
	t2.sqr(t4)
	bx.mul(t1, t2)
	t2.sub(t1, t2)
	bz.mulSmall(t2, 121665)
	t1.add(t1, bz)
	bz.mul(t1, t2)
}

/* Y^2 = X^3 + 486662 X^2 + X
 * t is a temporary  */
func (y2 *long10) xToY2(x, t *long10) {
	if t == nil {
		t = new(long10)
	}
	t.sqr(x)
	y2.mulSmall(x, 486662)
	t.add(t, y2)
	t[0]++
	y2.mul(t, x)
}

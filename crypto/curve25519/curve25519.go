package curve25519

import "bytes"

/* group order (a prime near 2^252+2^124) */
var order = []byte{
	237, 211, 245, 92, 26, 99, 18, 88,
	214, 156, 247, 162, 222, 249, 222, 20,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 16,
}

/* smallest multiple of the order that's >= 2^255 */
var orderTimes8 = []byte{
	104, 159, 174, 231, 210, 24, 147, 192,
	178, 230, 188, 23, 245, 206, 247, 166,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 128,
}

/* Private key clamping
 *   k [out] your private key for key agreement
 *   k [in]  32 random bytes
 */
func clamp(k []byte) {
	k[31] &= 0x7F
	k[31] |= 0x40
	k[0] &= 0xF8
}

/* Key-pair generation
 *   P  [out] your public key
 *   s  [out] your private key for signing, may be nil if you don't care
 *   k  [out] your private key for key agreement
 *   k  [in]  32 random bytes
 *
 * WARNING: if s is not NULL, this function has data-dependent timing */
func keygen(P, s, k []byte) {
	clamp(k)
	core(P, s, k, nil)
}

/* Key agreement
 *   Z  [out] shared secret (needs hashing before use)
 *   k  [in]  your private key for key agreement
 *   P  [in]  peer's public key
 */
func curve(Z, k, P []byte) {
	core(Z, nil, k, P)
}

/* P = kG  and s = sign(P)/k  */
func core(Px, s, k, Gx []byte) {
	dx := new(long10)
	t1 := new(long10)
	t2 := new(long10)
	t3 := new(long10)
	t4 := new(long10)

	x := [2]*long10{new(long10), new(long10)}
	z := [2]*long10{new(long10), new(long10)}

	/* unpack the base */
	if Gx != nil {
		dx.unpack(Gx)

	} else {
		dx.set(9)
	}

	/* 0G = point-at-infinity */
	x[0].set(1)
	z[0].set(0)

	/* 1G = G */
	x[1].cpy(dx)
	z[1].set(1)

	for i := 31; i >= 0; i-- {
		for j := 7; j >= 0; j-- {
			/* swap arguments depending on bit */
			uj := uint(j)
			bit1 := (k[i] & 0xFF) >> uj & 1
			bit0 := ^(k[i] & 0xFF) >> uj & 1

			ax := x[bit0]
			az := z[bit0]
			bx := x[bit1]
			bz := z[bit1]

			/* a' = a + b */
			/* b' = 2 b */
			montPrep(t1, t2, ax, az)
			montPrep(t3, t4, bx, bz)
			montAdd(t1, t2, t3, t4, ax, az, dx)
			montDbl(t1, t2, t3, t4, bx, bz)
		}
	}

	t1.recip(z[0], false)
	dx.mul(x[0], t1)
	dx.pack(Px)

	/* calculate s such that s abs(P) = G  .. assumes G is std base point */
	if s != nil {
		t1.xToY2(dx, t2)      /* t1 = Py^2  */
		t3.recip(z[1], false) /* where Q=P+G ... */
		t2.mul(x[1], t3)      /* t2 = Qx  */
		t2.add(t2, dx)        /* t2 = Qx + Px  */
		t2[0] += 9 + 486662   /* t2 = Qx + Px + Gx + 486662  */
		dx[0] -= 9            /* dx = Px - Gx  */
		t3.sqr(dx)            /* t3 = (Px - Gx)^2  */
		dx.mul(t2, t3)        /* dx = t2 (Px - Gx)^2  */
		dx.sub(dx, t1)        /* dx = t2 (Px - Gx)^2 - Py^2  */
		dx[0] -= 39420360     /* dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  */
		t1.mul(dx, baseR2y)   /* t1 = -Py  */
		if t1.isNegative() {  /* sign is 1, so just copy  */
			copy(s, k)
		} else { /* sign is -1, so negate  */
			mulaSmall(s, orderTimes8, 0, k, 32, -1)
		}

		/* reduce s mod q
		 * (is this needed?  do it just in case, it's fast anyway) */
		//divmod((dstptr) t1, s, 32, order25519, 32);

		/* take reciprocal of s mod q */
		temp1 := make([]byte, 32)
		temp2 := make([]byte, 64)
		temp3 := make([]byte, 64)
		copy(temp1, order)
		copy(s, egcd32(temp2, temp3, s, temp1))
		if (s[31] & 0x80) != 0 {
			mulaSmall(s, s, 0, order, 32, 1)
		}
	}
}

/* deterministic EC-KCDSA
 *
 *    s is the private key for signing
 *    P is the corresponding public key
 *    Z is the context data (signer public key or certificate, etc)
 *
 * signing:
 *
 *    m = hash(Z, message)
 *    x = hash(m, s)
 *    keygen25519(Y, NULL, x);
 *    r = hash(Y);
 *    h = m XOR r
 *    sign25519(v, h, x, s);
 *
 *    output (v,r) as the signature
 *
 * verification:
 *
 *    m = hash(Z, message);
 *    h = m XOR r
 *    verify25519(Y, v, h, P)
 *
 *    confirm  r == hash(Y)
 *
 * It would seem to me that it would be simpler to have the signer directly do
 * h = hash(m, Y) and send that to the recipient instead of r, who can verify
 * the signature by checking h == hash(m, Y).  If there are any problems with
 * such a scheme, please let me know.
 *
 * Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of
 * perfectly good entropy, but does allow Y to be calculated in advance of (or
 * parallel to) hashing the message.
 */

/* Signature generation primitive, calculates (x-h)s mod q
 *   v  [out] signature value
 *   h  [in]  signature hash (of message, signature pub key, and context data)
 *   x  [in]  signature private key
 *   s  [in]  private key for signing
 * returns true on success, false on failure (use different x or h)
 */
func sign(v, h, x, s []byte) bool {
	// v = (x - h) s  mod q
	h1 := make([]byte, 32)
	x1 := make([]byte, 32)
	tmp1 := make([]byte, 64)
	tmp2 := make([]byte, 64)
	tmp3 := make([]byte, 32)

	// Don't clobber the arguments, be nice!
	copy(h1, h)
	copy(x1, x)

	// Reduce modulo group order
	divmod(tmp3, h1, 32, order, 32)
	divmod(tmp3, x1, 32, order, 32)

	// v = x1 - h1
	// If v is negative, add the group order to it to become positive.
	// If v was already positive we don't have to worry about overflow
	// when adding the order because v < ORDER and 2*ORDER < 2^256
	mulaSmall(v, x1, 0, h1, 32, -1)
	mulaSmall(v, v, 0, order, 32, 1)

	// tmp1 = (x-h)*s mod q
	mula32(tmp1, v, s, 32, 1)
	divmod(tmp2, tmp1, 64, order, 32)
	w := byte(0)
	for i := 0; i < 32; i++ {
		v[i] = tmp1[i]
		w |= tmp1[i]
	}
	return w != 0
}

/* Signature verification primitive, calculates Y = vP + hG
 *   Y  [out] signature public key
 *   v  [in]  signature value
 *   h  [in]  signature hash
 *   P  [in]  public key
 */
func verify(Y, v, h, P []byte) {
	/* Y = v abs(P) + h G  */
	d := make([]byte, 32)
	p := [2]*long10{new(long10), new(long10)}
	s := [2]*long10{new(long10), new(long10)}
	yx := [3]*long10{new(long10), new(long10), new(long10)}
	yz := [3]*long10{new(long10), new(long10), new(long10)}
	t1 := [3]*long10{new(long10), new(long10), new(long10)}
	t2 := [3]*long10{new(long10), new(long10), new(long10)}

	/* set p[0] to G and p[1] to P  */

	p[0].set(9)
	p[1].unpack(P)

	/* set s[0] to P+G and s[1] to P-G  */

	/* s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */
	/* s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */

	t2[0].xToY2(p[1], t1[0]) /* t2[0] = Py^2  */
	t1[0].sqrt(t2[0])        /* t1[0] = Py or -Py  */
	j := 0
	if t1[0].isNegative() {
		j = 1
	}
	t2[0][0] += 39420360      /* t2[0] = Py^2 + Gy^2  */
	t2[1].mul(base2y, t1[0])  /* t2[1] = 2 Py Gy or -2 Py Gy  */
	t1[j].sub(t2[0], t2[1])   /* t1[0] = Py^2 + Gy^2 - 2 Py Gy  */
	t1[1-j].add(t2[0], t2[1]) /* t1[1] = Py^2 + Gy^2 + 2 Py Gy  */
	t2[0].cpy(p[1])           /* t2[0] = Px  */
	t2[0][0] -= 9             /* t2[0] = Px - Gx  */
	t2[1].sqr(t2[0])          /* t2[1] = (Px - Gx)^2  */
	t2[0].recip(t2[1], false) /* t2[0] = 1/(Px - Gx)^2  */
	s[0].mul(t1[0], t2[0])    /* s[0] = t1[0]/(Px - Gx)^2  */
	s[0].sub(s[0], p[1])      /* s[0] = t1[0]/(Px - Gx)^2 - Px  */
	s[0][0] -= 9 + 486662     /* s[0] = X(P+G)  */
	s[1].mul(t1[1], t2[0])    /* s[1] = t1[1]/(Px - Gx)^2  */
	s[1].sub(s[1], p[1])      /* s[1] = t1[1]/(Px - Gx)^2 - Px  */
	s[1][0] -= 9 + 486662     /* s[1] = X(P-G)  */
	s[0].mulSmall(s[0], 1)    /* reduce s[0] */
	s[1].mulSmall(s[1], 1)    /* reduce s[1] */

	/* prepare the chain  */
	var vi, hi, di, nvh int
	for i := 0; i < 32; i++ {
		vi = (vi >> 8) ^ int(v[i]&0xFF) ^ (int(v[i]&0xFF) << 1)
		hi = (hi >> 8) ^ int(h[i]&0xFF) ^ (int(h[i]&0xFF) << 1)
		nvh = ^(vi ^ hi)
		di = (nvh & ((di & 0x80) >> 7)) ^ vi
		di ^= nvh & ((di & 0x01) << 1)
		di ^= nvh & ((di & 0x02) << 1)
		di ^= nvh & ((di & 0x04) << 1)
		di ^= nvh & ((di & 0x08) << 1)
		di ^= nvh & ((di & 0x10) << 1)
		di ^= nvh & ((di & 0x20) << 1)
		di ^= nvh & ((di & 0x40) << 1)
		d[i] = byte(di)
	}

	di = ((nvh & ((di & 0x80) << 1)) ^ vi) >> 8

	/* initialize state */
	yx[0].set(1)
	yx[1].cpy(p[di])
	yx[2].cpy(s[0])
	yz[0].set(0)
	yz[1].set(1)
	yz[2].set(1)

	/* y[0] is (even)P + (even)G
	 * y[1] is (even)P + (odd)G  if current d-bit is 0
	 * y[1] is (odd)P + (even)G  if current d-bit is 1
	 * y[2] is (odd)P + (odd)G
	 */

	vi = 0
	hi = 0

	/* and go for it! */
	for i := 31; i >= 0; i-- {
		vi = (vi << 8) | int(v[i]&0xFF)
		hi = (hi << 8) | int(h[i]&0xFF)
		di = (di << 8) | int(d[i]&0xFF)
		for j = 7; j >= 0; j-- {
			montPrep(t1[0], t2[0], yx[0], yz[0])
			montPrep(t1[1], t2[1], yx[1], yz[1])
			montPrep(t1[2], t2[2], yx[2], yz[2])

			uj := uint(j)
			k := ((vi ^ vi>>1) >> uj & 1) + ((hi ^ hi>>1) >> uj & 1)
			montDbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0])
			k = (di >> uj & 2) ^ ((di >> uj & 1) << 1)
			montAdd(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1], p[di>>uj&1])
			montAdd(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2], s[((vi^hi)>>uj&2)>>1])
		}
	}

	k := (vi & 1) + (hi & 1)
	t1[0].recip(yz[k], false)
	t1[1].mul(yx[k], t1[0])
	t1[1].pack(Y)
}

func isCanonicalSignature(v []byte) bool {
	if len(v) < 32 {
		return false
	}
	vCopy := append(v[:0:0], v[:32]...)
	divmod(make([]byte, 32), vCopy, 32, order, 32)
	return bytes.Equal(vCopy, v[:32])
}

func isCanonicalPublicKey(P []byte) bool {
	if len(P) != 32 {
		return false
	}

	rawP := new(long10)
	rawP.unpack(P)
	PCopy := rawP.pack(nil)
	return bytes.Equal(PCopy, P)
}

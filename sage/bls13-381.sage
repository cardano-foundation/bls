# parameters for BLS12-381 
z = -0xd201000000010000
q = (z^4 - z^2 + 1)
p = ZZ( z + q*(z - 1)^2/3 )
h1 = ZZ( (z - 1)^2 / 3 )
h2 = ZZ( (z^8 - 4*z^7 + 5*z^6 - 4*z^4 + 6*z^3 - 4*z^2-4*z + 13) / 9 )

F = GF(p)
F12.<T> = GF(p^12)
RF.<T> = PolynomialRing(F12)
j = (T^2 + 1).roots(ring=F12, multiplicities=0)[0]

E0 = EllipticCurve(F  , [0, 4])
E1 = EllipticCurve(F12, [0, 4])
E2 = EllipticCurve(F12, [0, 4 + 4*j])

# Generators of G1 and G2 (from https://aandds.com/blog/bls.html)
x1 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
y1 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
g1 = E1( (x1, y1) )
x2 = ( 0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
      + 0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E * j )
y2 = ( 0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801
      + 0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE * j )
g2 = E2( (x2, y2) )

iso = E2.isomorphism_to(E1)
k = 12
t = p + 1 - E0.order()

# Returns ate pairing for scalar points p1 and p2 that must be between 0 and q - 1
def atePairing(p1, p2):
    if ( p1 < 0 and p1 >= q ):
        print ("p1 must be between 0 and %d", q )
    if ( p2 < 0 and p2>= q ):
        print ("p2 must be between 0 and %d", q )    
    return((p1*g1).ate_pairing(iso(p2*g2), q, k, t, p))
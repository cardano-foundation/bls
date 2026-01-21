# BLS multi-signatures cryptographic tools

## Contents
1. [Introduction](#high-level-introduction)
2. [BLS12-381 Elliptic curve overview](#bls-elliptic-curves-overview)
3. [BLS12-381 Elliptic curve golden in sagemath](#bls12-381-elliptic-curve-golden)

## High level introduction

**BLS** abbreviation stands for names of inventors of the scheme, ie., Boneh-Lynn-Shacham, that proposed the scheme in the
[Short signatures from the Weil pairing](https://mit6875.github.io/FA23HANDOUTS/boneh-lynn-shacham.pdf) paper.

### Secret, public key and pairing as a check

The scheme works for pairings-friendly elliptic curves within which two groups are chosen,  _G1_ and _G2_, with generators _g1_ and _g2_, respectively.
The secret key *sk* is then the number randomly picked between _1_ and _order(G1)_. The corresponding public key is

$pk=sk*g_2$

Having hashing function, $H(msg)*g_1$, we can get signature,

$sig=sk*H(msg)*g_1$

Given a pairing, _e_, verification is checking the equality

$e(H(m)*g_1,pk)==e(sig,g_2)$

Please notice that in any pairing we have elements from two groups, _G1_ and _G2_, the pairing shares.
And due to bilinearity property of the pairing the following holds

```math
e(H(m)*g_1,pk)=e(sk*H(m)*g_1,g_2)=e(sig, g_2)
```

The choices of representation of the different entities are not random and carefully picked. _G2_ is defined over the quadratic
extention of the field and hence the storage demands are larger for _G2_ elements than for elements of _G1_. The arithmetic requirements are harsher for _G2_ in comparison with _G1_.
If we are to store all public keys in application then it would be tempting to represent them in _G1_. If we are to store signatures then it is advantageous to
stick to the scheme proposed above. Especially, if **public keys could be aggregated** (as is the case for multi-signature).
Another performance dimension to ponder the verification of the scheme, as normally pairing operation is costly. Especially if we compare it to other elliptic curve signature schemes like
_Schnorr_ or _EdDSA_. However, as BLS allows for **signature aggregation**, which is not so straightforward in other schemes mentioned, the comparison picture changes dramatically in favor of BLS,
especially for big number multi-party cases (like voting).

The BLS scheme is [IEFT drafted](https://github.com/cfrg/draft-irtf-cfrg-bls-signature) and here we are aimimng to comply with it.

### Aggregate signature case

Let's assume we have _n_ participants that sign n **different** messages (each participant _i_ signs a different and single message $m_i$). Then we have n signatures
$sig_i$ for i=0..n-1. The aggregate signature is then

$\sum_{n=0}^{n-1} sig_i = sig_{agg}$

The verification requires the following pairing as a consequence

```math
e(H(m_0)*g_1,pk_0)*...*e(H(m_{n-1})*g_1,pk_{n-1})=e(sig_{agg}, g_2)
```

Meaning _n-1_ less pairing evaluation during verification thanks to $sig_{agg}$ .

### Aggregate signature and public key case

In multi-signature case, in addition to signature aggregation sketched above, all the signers sign **THE SAME** message.
In that case, we can aggregate also public keys:

$\sum_{n=0}^{n-1} pk_i = pk_{agg}$

and just two pairing evaluations on the verification side: 

```math
e(sig_{agg}, g_2)=e(H(m), pk_{agg})
```

And this is regardless of the number of signatures engaged. 

## BLS elliptic curves overview

Although the same abbreviation, BLS here, stands for Barreto-Lynn-Scott. The family of curves was introduced in this [seminal paper](https://eprint.iacr.org/2002/088.pdf).
BLS12-381 curve was proposed by [Sean Bowe in the context of ZCash](https://electriccoin.co/blog/new-snark-curve/).
The usage of this curve was adopted in number of other blockchains, like Ethereum 2.0, Skale, Algorand, Dfinity or Chia.
There is also support of this curve in Cardano, see for example, [cardano-crypto-class](https://github.com/IntersectMBO/cardano-base/tree/master/cardano-crypto-class) and the curve is exposed also in [aiken from 3.0 release](https://aiken-lang.github.io/stdlib/aiken/crypto.html). The great introduction and motivation for this curve was written in the blog post [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381#Motivation).
It is especially worth mentioning and repeating that the elliptic curve BLS12-381 is currently in [IETF draft revision 12](https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/12/) stage of ratification.

## BLS12-381 elliptic curve golden

The golden are generated using _SageMath_.

<details>
<summary>
In order to run it do the following:
Download the latest image from docker hub and run the image in Linux CLI </summary>

```bash
$ docker image pull sagemath/sagemath:latest
$ docker run -it sagemath/sagemath:latest
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.6, Release Date: 2025-03-31                    │
│ Using Python 3.12.5. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: ZZ(1234)
1234
sage: ZZ.random_element(10**10)
4134169080
sage: quit
```
</details>

<details>
<summary>
Definition of the `g1` and `g2` generators of BLS12-381 are as follows </summary>

```sagemath
$ docker run -it sagemath/sagemath:latest
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 10.6, Release Date: 2025-03-31                    │
│ Using Python 3.12.5. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: # parameters for BLS12-381 
sage: z = -0xd201000000010000
sage: q = (z^4 - z^2 + 1)
sage: p = ZZ( z + q*(z - 1)^2/3 )
sage: h1 = ZZ( (z - 1)^2 / 3 )
sage: h2 = ZZ( (z^8 - 4*z^7 + 5*z^6 - 4*z^4 + 6*z^3 - 4*z^2-4*z + 13) / 9 )
sage: 
sage: F = GF(p)
sage: F12.<T> = GF(p^12)
sage: RF.<T> = PolynomialRing(F12)
sage: j = (T^2 + 1).roots(ring=F12, multiplicities=0)[0]
sage: 
sage: E0 = EllipticCurve(F  , [0, 4])
sage: E1 = EllipticCurve(F12, [0, 4])
sage: E2 = EllipticCurve(F12, [0, 4 + 4*j])
sage: 
sage: # Generators of G1 and G2 (from https://aandds.com/blog/bls.html)
sage: x1 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
sage: y1 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
sage: g1 = E1( (x1, y1) )
sage: g1
(3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 : 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569 : 1)
sage:
sage: x2 = ( 0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
....:        + 0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E * j )
sage: y2 = ( 0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801
....:        + 0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE * j )
sage: g2 = E2( (x2, y2) )
sage: g2
(1524974934786634869148131047310421674182836367449173499629923666942270478173692664531820817762762612344409858914964*T^11 + 466951167399357819139631101904986341224981495609714517635702448944519312260109086445781162685798203428334155880880*T^10 + 1944629476307696029264710266106104663569401282758349834035384266803502880053233596923517745604293008606776526438813*T^9 + 1064375233906181771446477941731343550152603669242299152704511736901490138163467666912330935749112285497156761812752*T^8 + 524439736117802807566493065558956839033117050732954679474969089293280892348176067052922254028348973140488064346680*T^7 + 139299954118351620793346869471477340669710886265406598127176113079273670344633842262233554267773747834887844661959*T^6 + 739103731826146034717518476459285826868296267538760008155772915279505351525517068683802447801310475600017832001536*T^5 + 896579657303157448006189552190113634690581086624769337632713495534809460193116759284265739854449610289932037083511*T^4 + 843441423355824479944600244225871554713741591724364436154026866899150457470952385866750976645325703303081742979949*T^3 + 1795103225418651429974471490460265646267542049407206684864372758871936629575790147152120418625946616733733618740492*T^2 + 2270793357157838349634671710596689517815160546326318444928655212579690005846921471457165730885514293745964204026559*T + 813014002142981337674656983069970178581719823359786819712640294232766489286415435462948748861707183513679546469441 : 2233067595893406183140797165166489187100525817059352259655242619220390811216367457646110522297226695114452618126428*T^11 + 3602614435636483318959443118205040525998181781525417444771234468139389445877844421472824706983321089450546400870408*T^10 + 3224615712555652661084560310165376476019389757955167724510331501326401626808233747552484652698863330443680962820917*T^9 + 3040382335659451540384754154091661048671599534370655708704703502867830592626379244694086346412062450671231887885165*T^8 + 1459659623750766938694911649253051666276457273093410738960223584589040835447263007618656734237877869272906176926781*T^7 + 525539455293034032098934334132168443354191087251408822811190076148987847200277414420473133234996624365757081282351*T^6 + 1935177694213014925357296420933743720542489252007361846327337055240415803856062332714083431876300729313471329470580*T^5 + 2883239579362127280123556510406854355370944137906162523152958865339387964290988651876855569182930991824507652232201*T^4 + 3942619066893923403018401938436688648248629145749936849043252750084173495049199745561763979760261815776889173528081*T^3 + 1562914866630349508139782242415445213834899573426278635127828361112177413806119582983372787156016586380048149693338*T^2 + 3946024511249678960209495574926206734629277115261246062005271561516945960048572293854026584408693323374250148250856*T + 1779832377062937975389417919695747609689924901440156773060063840000543320473223795889149116063583645025352965406497 : 1)
sage: 
sage: iso = E2.isomorphism_to(E1)
sage: k = 12
sage: t = p + 1 - E0.order()
sage: 
sage: # points to multiply
sage: p1 = 3 * g1
sage: p2 = 7 * g2
sage: 
sage: pairing = p1.ate_pairing(iso(p2), q, k, t, p)
sage: pairing
1387761180978465257476112114847050954511272727021099751707596163090778868843287264887355898156219205646615919788244*T^11 + 1446883575202745040098524998028928188805352441437568605052309003251474833797606339941486005555318295253400449574856*T^10 + 2289356806038184996098713895627084599608283630602663106285535398352867141005601228479347752163145019775636427532012*T^9 + 2487614079649481926416133165448060373372038984938567333577088685317194994073514077232317052321035343791904288247011*T^8 + 3891489328650613869705581914768326688234963543838784031259079251868391300774640519753311173801252953172526822462240*T^7 + 2792435783690433507322189459793051724616954530788354556430819738993112816271592147652996357392630213749489308344656*T^6 + 35111015063507576537592258024431898995755574791121590952023315776751558722050703078334586598819155440635689457708*T^5 + 3783727747182150558562944473240659236675859510095494968580243950919574561954505301371192111500101903932407599056565*T^4 + 873402532902248026825383537764981810447641615734420576800986113571738141480823045073770061259201908983957151880729*T^3 + 2430362863288168000692601594281896253332164292488455504070262876362492167147322899004470395947057992498301611345961*T^2 + 2516516254775662282437328395604952307303479769942541843868334037694383243351020382033415642349702330543329895558588*T + 77785235024769787806807078473160298793133394833594108256424752936500989374455064079184800642853717318883162085283
sage: # bilinearity property of pairings
sage: s = Integer(randrange(1, q))
sage: s
8884357174281045537091591028472861979113457994414036960833850102221027530006
sage: (s*p1).ate_pairing(iso(p2), q, k, t, p) == p1.ate_pairing(iso(s*p2), q, k, t, p)
True
```
</details>

<details>
<summary>How to load sage definitions in docker containers</summary>

```bash
docker run -v /local/path/to/bls/sage:/data -it sagemath/sagemath:latest
```

```sagemath
sage: load('/data/bls13-381.sage')
sage: # the above-mentioned definitions are now available
sage:
sage: # point from G1
sage: p1=3*g1
sage: # point from G2
sage: p2=7*g2
atePairing(p1, p2)
1387761180978465257476112114847050954511272727021099751707596163090778868843287264887355898156219205646615919788244*T^11 + 1446883575202745040098524998028928188805352441437568605052309003251474833797606339941486005555318295253400449574856*T^10 + 2289356806038184996098713895627084599608283630602663106285535398352867141005601228479347752163145019775636427532012*T^9 + 2487614079649481926416133165448060373372038984938567333577088685317194994073514077232317052321035343791904288247011*T^8 + 3891489328650613869705581914768326688234963543838784031259079251868391300774640519753311173801252953172526822462240*T^7 + 2792435783690433507322189459793051724616954530788354556430819738993112816271592147652996357392630213749489308344656*T^6 + 35111015063507576537592258024431898995755574791121590952023315776751558722050703078334586598819155440635689457708*T^5 + 3783727747182150558562944473240659236675859510095494968580243950919574561954505301371192111500101903932407599056565*T^4 + 873402532902248026825383537764981810447641615734420576800986113571738141480823045073770061259201908983957151880729*T^3 + 2430362863288168000692601594281896253332164292488455504070262876362492167147322899004470395947057992498301611345961*T^2 + 2516516254775662282437328395604952307303479769942541843868334037694383243351020382033415642349702330543329895558588*T + 77785235024769787806807078473160298793133394833594108256424752936500989374455064079184800642853717318883162085283
```
</details>


<details>
<summary>Secret, public key and verification pairing scheme</summary>

```sagemath
sage: load('/data/bls13-381.sage')
sage: # prover generates sk and calculates corresponding pk
sage: sk = Integer(randrange(1, E1.order()))
sage: sk
13663622035249999109513796709535022818204304616220558708912565044945058489634024331354766144405089808542334453214885898724206213260782201221743317452788136660011389678255250803597611351201606475516418510793232081394246668498850358555442965033671279401563657165901122065076397973549723722098985040162697722588752124834932870081367603741659373960803179726462161817667903793529082794031789389906154714427457741530664789096774806023819770728387966723250545009329591839146846600158804763629087089060932134420089585839502047561040382283315604397522495184161447901443335373058105716222354826614815814091591511653740069156175744327292848797787647834591079166886915137967893529279925420169919181050765307104049612981505310255671736005248119196536715561680810373282898612915054400559983629951690909595352101526366645079313323514017863445460158607477758109938267213348668987920090758658161367873458672041449087137754112980773507470221038681333134543991421916959464320580714983930859760174691464945012261997691432132090473171953375225129434098275424145265972978460354569596329740233599858393607594229350340499573265176358325082511555203657456141315499920592888448797927739169637082989702957705803552546850731778058778755641143442619542132802530809686724736145634481631178394687622802301187685860010174267845014070405120393290072036772459218644652808484325019895941966887638217095861482509
sage: pk=sk*g2
sage: # due to asymmentry it is extremely difficult to go from pk to sk. Prover hid its sk in point of G2 
sage: # now for the sake of simplicity let's assume prover has hash of msg Hmsg=111
sage: # we will have H point from group G1
sage: Hmsg=111
sage: Hpoint=Hmsg*g1
sage: #signature is 
sage: sig = sk * Hpoint
sage: # verification requires the calculation of two pairings and comparing them
sage: left = atePairing(Hpoint,pk)
sage: right = atePairing(sig,g2)
sage: left == right
True

# Verifier receives 3 points, Hpoint, pk, and sig and calculates two pairings to verify
# Prover has secret sk, calculates pk point from sk. Having msg also calculates hash and maps it to point.
# signature is multiplication operation between sk and the hash point.
# Caution/disclaimer: hash-to-point is naively calculated here for education purposes. 
```
</details>

<details>
<summary>Aggregate signature case</summary>

```sagemath
sage: load('/data/bls13-381.sage')
sage: # Two parties represented by secrets, sk1 and sk2
sage: sk1 = Integer(randrange(1, E1.order()))
sage: sk2 = Integer(randrange(1, E1.order()))
sage: # Two parties represented by the respective public keys, pk1 and pk2
sage: pk1=sk1*g2
sage: pk2=sk2*g2
sage
sage: sk1 == sk2
False
sage: # Let's assume that hashes of two msgs are
sage: Hmsg1=111
sage: Hmsg2=222
sage: # which could be mapped into points of G1
sage: Hpoint1=Hmsg1*g1
sage: Hpoint2=Hmsg2*g1
sage:
sage: # signatures
sage: sig1 = sk1 * Hpoint1
sage: sig2 = sk2 * Hpoint2
sage: sigAggr = sig1 + sig2
sage:
sage: # verification
sage: left1 = atePairing(Hpoint1,pk1)
sage: left2 = atePairing(Hpoint2,pk2)
sage: right = atePairing(sigAggr,g2)
sage: left1*left2 == right
True
```

</details>

<details>
<summary>Aggregate signature case</summary>

```sagemath
sage: load('/data/bls13-381.sage')
sage: # Two parties represented by secrets, sk1 and sk2
sage: sk1 = Integer(randrange(1, E1.order()))
sage: sk2 = Integer(randrange(1, E1.order()))
sage: # Two parties represented by the respective public keys, pk1 and pk2
sage: pk1=sk1*g2
sage: pk2=sk2*g2
sage: pkAggr = pk1 + pk2
sage
sage: sk1 == sk2
False
sage: # Let's assume that hashes of ONE msg are
sage: Hmsg=111
sage: # which could be mapped into point of G1
sage: Hpoint=Hmsg*g1
sage:
sage: sig1 = sk1 * Hpoint
sage: sig2 = sk2 * Hpoint
sage: sigAggr = sig1 + sig2
sage:
sage: # verification of aggregates
sage: left = atePairing(Hpoint,pkAggr)
sage: right = atePairing(sigAggr,g2)
sage: left == right
True
```

</details>

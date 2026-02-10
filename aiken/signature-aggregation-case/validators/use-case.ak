use bls/g2_basic.{ skToPk, sign, verify}

test test_bls () {
  let sk = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let pk = skToPk(sk)
  let message = "Hello, Aiken!"

  let signature = sign(sk, message)

  verify(pk, message, signature)
}
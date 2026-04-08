use vrf/core as vrf

test test_basic_vrf_proving () {
  let secret = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let sk1 = vrf.secret_scalar(secret, "")
  let (sk2, _pk) = vrf.keys_from_secret(secret)

  sk1 == sk2
}
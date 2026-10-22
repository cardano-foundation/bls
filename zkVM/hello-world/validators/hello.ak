use aiken/crypto.{sha2_256}

pub fn hello_hash(msg: ByteArray) -> ByteArray {
  sha2_256(msg)
}

test hello_hash_hello_world() {
  hello_hash("Hello, world!") == #"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
}

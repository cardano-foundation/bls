#[cfg(test)]
mod tests {
    use crate::encoder::{encode_data_blob, DataArg, encode_vrf_secret};
    use crate::runner::{RunConfig, VmTarget};

    #[test]
    fn test_encode_data_b() {
        let data = DataArg::B(vec![1, 2, 3]);
        let blob = encode_data_blob(&data);
        assert_eq!(blob[0], 0);
        assert_eq!(blob[1..5], (3u32).to_le_bytes());
        assert_eq!(&blob[5..8], &[1, 2, 3]);
    }

    #[test]
    fn test_encode_data_i() {
        let data = DataArg::I(42);
        let blob = encode_data_blob(&data);
        assert_eq!(blob[0], 1);
    }

    #[test]
    fn test_encode_data_list() {
        let data = DataArg::List(vec![DataArg::B(vec![1]), DataArg::B(vec![2])]);
        let blob = encode_data_blob(&data);
        assert_eq!(blob[0], 2);
    }

    #[test]
    fn test_encode_data_constr() {
        let data = DataArg::Constr(0, vec![DataArg::B(vec![1])]);
        let blob = encode_data_blob(&data);
        assert_eq!(blob[0], 4);
    }

    #[test]
    fn test_encode_vrf_secret() {
        let secret = "ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c";
        let data = encode_vrf_secret(secret).unwrap();
        match data {
            DataArg::B(b) => assert_eq!(b.len(), 32),
            _ => panic!("expected bytes"),
        }
    }

    #[test]
    fn test_run_config() {
        let config = RunConfig::new(VmTarget::OpenVM, "../hello-world/hello_hash.flat".to_string())
            .with_args(vec!["48656c6c6f2c20776f726c6421".to_string()]);
        assert_eq!(config.args_hex.len(), 1);
    }
}

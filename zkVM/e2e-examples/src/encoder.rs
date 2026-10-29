use crate::error::Result;

#[derive(Debug, Clone)]
pub enum DataArg {
    B(Vec<u8>),
    I(i128),
    List(Vec<DataArg>),
    Map(Vec<(DataArg, DataArg)>),
    Constr(u64, Vec<DataArg>),
}

pub fn encode_data_blob(data: &DataArg) -> Vec<u8> {
    let mut out = Vec::new();
    encode_data(&mut out, data);
    out
}

fn encode_data(out: &mut Vec<u8>, data: &DataArg) {
    match data {
        DataArg::B(bytes) => {
            out.push(0);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        DataArg::I(i) => {
            out.push(1);
            let bytes = i.to_le_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        DataArg::List(items) => {
            out.push(2);
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for item in items {
                encode_data(out, item);
            }
        }
        DataArg::Map(entries) => {
            out.push(3);
            out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            for (k, v) in entries {
                encode_data(out, k);
                encode_data(out, v);
            }
        }
        DataArg::Constr(tag, fields) => {
            out.push(4);
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
            for field in fields {
                encode_data(out, field);
            }
        }
    }
}

pub fn encode_vrf_secret(secret_hex: &str) -> Result<DataArg> {
    let bytes = hex::decode(secret_hex).map_err(|e| crate::error::Error::Encoding(e.to_string()))?;
    Ok(DataArg::B(bytes))
}

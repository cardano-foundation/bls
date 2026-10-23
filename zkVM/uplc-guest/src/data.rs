use alloc::vec::Vec;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    Constr(u64, Vec<Data>),
    Map(Vec<(Data, Data)>),
    List(Vec<Data>),
    I(BigInt),
    B(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataError {
    UnexpectedEnd,
    InvalidIndefinite,
    InvalidTag(u64),
    TrailingBytes,
}

pub fn decode_cbor(bytes: &[u8]) -> Result<Data, DataError> {
    let mut decoder = CborDecoder { bytes, pos: 0 };
    let data = decoder.item()?;
    if decoder.pos != bytes.len() {
        return Err(DataError::TrailingBytes);
    }
    Ok(data)
}

struct CborDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborDecoder<'a> {
    fn byte(&mut self) -> Result<u8, DataError> {
        let byte = *self.bytes.get(self.pos).ok_or(DataError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DataError> {
        let end = self.pos.checked_add(len).ok_or(DataError::UnexpectedEnd)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DataError::UnexpectedEnd)?;
        self.pos = end;
        Ok(slice)
    }

    fn uint(&mut self, info: u8) -> Result<u64, DataError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => Ok(self.byte()? as u64),
            25 => {
                let bytes = self.take(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            26 => {
                let bytes = self.take(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            27 => {
                let bytes = self.take(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            31 => Err(DataError::InvalidIndefinite),
            _ => Err(DataError::InvalidIndefinite),
        }
    }

    fn item(&mut self) -> Result<Data, DataError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            0 => Ok(Data::I(BigInt::from(self.uint(info)?))),
            1 => {
                let value = self.uint(info)?;
                Ok(Data::I(-BigInt::from(value) - 1))
            }
            2 => {
                let len = self.uint(info)? as usize;
                Ok(Data::B(self.take(len)?.to_vec()))
            }
            4 => {
                let len = self.uint(info)? as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.item()?);
                }
                Ok(Data::List(items))
            }
            5 => {
                let len = self.uint(info)? as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push((self.item()?, self.item()?));
                }
                Ok(Data::Map(items))
            }
            6 => {
                let tag = self.uint(info)?;
                self.tagged(tag)
            }
            _ => Err(DataError::InvalidIndefinite),
        }
    }

    fn tagged(&mut self, tag: u64) -> Result<Data, DataError> {
        if (121..=127).contains(&tag) {
            return self.constr(tag - 121);
        }
        if (1280..=1400).contains(&tag) {
            return self.constr(tag - 1280 + 7);
        }
        if tag == 102 {
            let fields = self.item()?;
            let Data::List(mut fields) = fields else {
                return Err(DataError::InvalidTag(tag));
            };
            if fields.len() != 2 {
                return Err(DataError::InvalidTag(tag));
            }
            let field_list = fields.pop().unwrap();
            let tag_data = fields.pop().unwrap();
            let tag_value = fields_tag(&tag_data)?;
            let Data::List(field_list) = field_list else {
                return Err(DataError::InvalidTag(tag));
            };
            return Ok(Data::Constr(tag_value, field_list));
        }
        Err(DataError::InvalidTag(tag))
    }

    fn constr(&mut self, tag: u64) -> Result<Data, DataError> {
        let fields = self.item()?;
        let Data::List(fields) = fields else {
            return Err(DataError::InvalidTag(tag));
        };
        Ok(Data::Constr(tag, fields))
    }
}

fn fields_tag(data: &Data) -> Result<u64, DataError> {
    match data {
        Data::I(value) => value.to_u64().ok_or(DataError::InvalidTag(102)),
        _ => Err(DataError::InvalidTag(102)),
    }
}

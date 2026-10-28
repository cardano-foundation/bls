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

pub fn decode_cbor_with_length(bytes: &[u8]) -> Result<(Data, usize), DataError> {
    let mut decoder = CborDecoder { bytes, pos: 0 };
    let data = decoder.item()?;
    Ok((data, decoder.pos))
}

pub fn encode_cbor(data: &Data) -> Vec<u8> {
    let mut encoder = CborEncoder { out: Vec::new() };
    encoder.item(data);
    encoder.out
}

struct CborEncoder {
    out: Vec<u8>,
}

impl CborEncoder {
    fn item(&mut self, data: &Data) {
        match data {
            Data::Constr(tag, fields) => self.constr(*tag, fields),
            Data::Map(entries) => {
                self.head(5, entries.len() as u64);
                for (key, value) in entries {
                    self.item(key);
                    self.item(value);
                }
            }
            Data::List(items) => {
                self.head(4, items.len() as u64);
                for item in items {
                    self.item(item);
                }
            }
            Data::I(value) => self.integer(value),
            Data::B(bytes) => {
                self.head(2, bytes.len() as u64);
                self.out.extend_from_slice(bytes);
            }
        }
    }

    fn constr(&mut self, tag: u64, fields: &[Data]) {
        if tag <= 6 {
            self.head(6, 121 + tag);
        } else if tag <= 127 {
            self.head(6, 1280 + tag - 7);
        } else {
            self.head(6, 102);
            self.head(4, 2);
            self.integer(&BigInt::from(tag));
            self.head(4, fields.len() as u64);
            for field in fields {
                self.item(field);
            }
            return;
        }
        self.head(4, fields.len() as u64);
        for field in fields {
            self.item(field);
        }
    }

    fn integer(&mut self, value: &BigInt) {
        if let Some(unsigned) = value.to_u64() {
            self.head(0, unsigned);
        } else if let Some(signed) = value.to_i64() {
            // signed < 0 because to_u64 failed
            let encoded = (-signed - 1) as u64;
            self.head(1, encoded);
        } else {
            // Arbitrary precision: use CBOR bignum tags.
            let (sign, magnitude) = value.clone().into_parts();
            let bytes = magnitude.to_bytes_be();
            match sign {
                num_bigint::Sign::Plus | num_bigint::Sign::NoSign => {
                    self.head(6, 2); // positive bignum tag
                    self.head(2, bytes.len() as u64);
                    self.out.extend_from_slice(&bytes);
                }
                num_bigint::Sign::Minus => {
                    self.head(6, 3); // negative bignum tag
                    self.head(2, bytes.len() as u64);
                    self.out.extend_from_slice(&bytes);
                }
            }
        }
    }

    fn head(&mut self, major: u8, info: u64) {
        let major_shifted = major << 5;
        match info {
            0..=23 => self.out.push(major_shifted | info as u8),
            24..=0xff => {
                self.out.push(major_shifted | 24);
                self.out.push(info as u8);
            }
            0x100..=0xffff => {
                self.out.push(major_shifted | 25);
                self.out.extend_from_slice(&(info as u16).to_be_bytes());
            }
            0x10000..=0xffffffff => {
                self.out.push(major_shifted | 26);
                self.out.extend_from_slice(&(info as u32).to_be_bytes());
            }
            _ => {
                self.out.push(major_shifted | 27);
                self.out.extend_from_slice(&info.to_be_bytes());
            }
        }
    }
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

        if info == 31 {
            return self.indefinite(major);
        }

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
            3 => Err(DataError::InvalidIndefinite),
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

    fn indefinite(&mut self, major: u8) -> Result<Data, DataError> {
        match major {
            2 => {
                let mut bytes = Vec::new();
                loop {
                    let initial = self.byte()?;
                    if initial == 0xff {
                        break;
                    }
                    let len = self.uint(initial & 0x1f)? as usize;
                    bytes.extend_from_slice(self.take(len)?);
                }
                Ok(Data::B(bytes))
            }
            3 => Err(DataError::InvalidIndefinite),
            4 => {
                let mut items = Vec::new();
                loop {
                    if self.peek_break()? {
                        self.pos += 1;
                        break;
                    }
                    items.push(self.item()?);
                }
                Ok(Data::List(items))
            }
            5 => {
                let mut items = Vec::new();
                loop {
                    if self.peek_break()? {
                        self.pos += 1;
                        break;
                    }
                    items.push((self.item()?, self.item()?));
                }
                Ok(Data::Map(items))
            }
            _ => Err(DataError::InvalidIndefinite),
        }
    }

    fn peek_break(&self) -> Result<bool, DataError> {
        if self.pos >= self.bytes.len() {
            return Err(DataError::UnexpectedEnd);
        }
        Ok(self.bytes[self.pos] == 0xff)
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

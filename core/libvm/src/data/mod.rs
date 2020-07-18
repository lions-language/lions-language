use libtype::instruction::{AddressValue};

pub enum Data {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Address(AddressValue),
    Invalid
}



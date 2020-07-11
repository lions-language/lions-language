use super::{PrimevalType};

impl PrimevalType {
    pub fn to_str(&self) -> &'static str {
        match self {
            PrimevalType::Int8 => {
                "int8"
            },
            PrimevalType::Int16 => {
                "int16"
            },
            PrimevalType::Int32 => {
                "int32"
            },
            PrimevalType::Int64 => {
                "int64"
            },
            PrimevalType::Uint8 => {
                "uint8"
            },
            PrimevalType::Uint16 => {
                "uint16"
            },
            PrimevalType::Uint32 => {
                "uint32"
            },
            PrimevalType::Uint64 => {
                "uint64"
            },
            PrimevalType::Float32 => {
                "float32"
            },
            PrimevalType::Float64 => {
                "float64"
            },
            PrimevalType::Str => {
                "str"
            }
        }
    }
}

use super::{PrimevalType};

impl PrimevalType {
    pub fn to_str(&self) -> &'static str {
        match self {
            PrimevalType::Int8(_) => {
                "int8"
            },
            PrimevalType::Int16(_) => {
                "int16"
            },
            PrimevalType::Int32(_) => {
                "int32"
            },
            PrimevalType::Int64(_) => {
                "int64"
            },
            PrimevalType::Uint8(_) => {
                "uint8"
            },
            PrimevalType::Uint16(_) => {
                "uint16"
            },
            PrimevalType::Uint32(_) => {
                "uint32"
            },
            PrimevalType::Uint64(_) => {
                "uint64"
            },
            PrimevalType::Float32(_) => {
                "float32"
            },
            PrimevalType::Float64(_) => {
                "float64"
            },
            PrimevalType::Str(_) => {
                "str"
            }
        }
    }
}

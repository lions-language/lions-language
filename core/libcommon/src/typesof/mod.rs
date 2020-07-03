#[derive(Debug)]
pub struct Structure {
    pub name: String
}

impl Structure {
    pub fn new(name: String) -> Self {
        Self {
            name: name
        }
    }
}

#[derive(Debug)]
pub enum PrimevalType {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float32,
    Float64,
    Str,
    Array,
    Map
}

#[derive(Debug)]
pub struct Primeval {
    pub typ: PrimevalType,
    pub ptr: bool
}

impl Primeval {
    pub fn new(typ: PrimevalType) -> Self {
        Self{
            typ: typ,
            ptr: false
        }
    }

    pub fn new_with_ptr(typ: PrimevalType, ptr: bool) -> Self {
        Self {
            typ: typ,
            ptr: ptr
        }
    }
}

#[derive(Debug)]
pub enum Type {
    /*
     * 原生类型
     * */
    Primeval(Primeval),
    /*
     * 结构体类型
     * */
    Structure(Structure)
}

pub mod function;


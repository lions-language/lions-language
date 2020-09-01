use crate::{Type, TypeValue
     , Primeval, TypeAddrType};
use crate::structure::{StructDefine};
use crate::primeval::{PrimevalType};

impl Type {
    pub fn to_str(&self) -> &str {
        match self.typ_ref() {
            TypeValue::Primeval(v) => {
                v.typ.to_str()
            },
            TypeValue::Structure(sp) => {
                sp.struct_obj_ptr.as_ref::<StructDefine>().name_ref()
            },
            TypeValue::Any => {
                consts::ANY_TYPE
            },
            TypeValue::Empty => {
                consts::EMPTY_TYPE
            },
            TypeValue::Null => {
                consts::NULL_TYPE
            }
        }
    }

    pub fn from_str(typ: &str) -> Type {
        Type::from_str_with_addrtyp(
            typ, TypeAddrType::Stack)
    }

    pub fn from_str_with_addrtyp(typ: &str
        , addr_typ: TypeAddrType) -> Type {
        match typ {
            "uint8"|"u8" => {
                Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint8))
                    , addr_typ)
            },
            "uint16"|"u16" => {
                Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint16))
                    , addr_typ)
            },
            "uint32"|"u32" => {
                Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint32))
                    , addr_typ)
            },
            "uint64"|"u64" => {
                Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint64))
                    , addr_typ)
            },
            "str"|"utf8" => {
                Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Str))
                    , addr_typ)
            },
            _ => {
                unimplemented!("from {} to Type", typ);
            }
        }
    }

    pub fn to_attrubute_str(&self) -> &str {
        self.attr_ref().to_str()
    }
}

mod consts;

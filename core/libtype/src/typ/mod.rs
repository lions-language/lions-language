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
                sp.struct_obj.as_ref().name_ref()
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

    pub fn from_str(typ: &str) -> Option<Type> {
        Type::from_str_with_addrtyp(
            typ, TypeAddrType::Stack)
    }

    pub fn from_str_with_addrtyp(typ: &str
        , addr_typ: TypeAddrType) -> Option<Type> {
        /*
         * 原生类型才可以在这里被匹配
         * 否则返回 None
         * */
        match typ {
            "uint8"|"u8" => {
                Some(Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint8))
                    , addr_typ))
            },
            "uint16"|"u16" => {
                Some(Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint16))
                    , addr_typ))
            },
            "uint32"|"u32" => {
                Some(Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint32))
                    , addr_typ))
            },
            "uint64"|"u64" => {
                Some(Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Uint64))
                    , addr_typ))
            },
            "str"|"utf8"|"string" => {
                Some(Type::new_with_addrtyp(TypeValue::Primeval(
                        Primeval::new(
                            PrimevalType::Str))
                    , addr_typ))
            },
            _ => {
                None
            }
        }
    }

    pub fn to_attrubute_str(&self) -> &str {
        self.attr_ref().to_str()
    }
}

mod consts;

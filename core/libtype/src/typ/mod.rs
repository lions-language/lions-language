use crate::{Type, TypeValue
    , Primeval, TypeAddrType
    , TypeAttrubute
    , AddressType
    , StructObject, Structure};
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

    pub fn addr_length(&self) -> usize {
        match self.typ_ref() {
            TypeValue::Structure(dp) => {
                dp.struct_obj_ref().as_ref().member_length()
            },
            _ => {
                0
            }
        }
    }

    pub fn from_struct(define: &StructDefine
        , addr_typ: TypeAddrType) -> Self {
        Type::new_with_addrtyp(TypeValue::Structure(
                Structure::new(
                    StructObject::from_ref(define)))
            , addr_typ)
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

    /*
     * 创建 非 堆 类型
     * */
    pub fn new(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Type::_new(typ, attr, TypeAddrType::Stack)
    }

    pub fn new_without_attr(typ: TypeValue) -> Self {
        Type::new(typ, TypeAttrubute::Empty)
    }

    pub fn new_with_addrtyp(typ: TypeValue
        , addr_typ: TypeAddrType) -> Self {
        Type::_new(typ, TypeAttrubute::Empty, addr_typ)
    }

    pub fn new_heap(typ: TypeValue, attr: TypeAttrubute) -> Self {
        Type::_new(typ, attr, TypeAddrType::Heap)
    }

    pub fn new_empty() -> Self {
        Type::_new(TypeValue::Empty, TypeAttrubute::Empty, TypeAddrType::Stack)
    }

    pub fn new_null() -> Self {
        Type::_new(TypeValue::Null, TypeAttrubute::Empty, TypeAddrType::Stack)
    }

    pub fn set_type_attribute(&mut self, attr: TypeAttrubute) {
        *&mut self.attr = attr;
    }

    pub fn to_address_type(&self) -> AddressType {
        match &self.addr_typ {
            TypeAddrType::Stack => {
                AddressType::Stack
            },
            TypeAddrType::Heap => {
                AddressType::Heap
            }
        }
    }

    fn _new(typ: TypeValue, attr: TypeAttrubute, addr_typ: TypeAddrType) -> Self {
        Self {
            typ: typ,
            attr: attr,
            addr_typ: addr_typ
        }
    }
}

mod consts;

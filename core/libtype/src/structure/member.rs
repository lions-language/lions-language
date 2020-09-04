use crate::{Type, TypeValue};
use super::{StructMember, StructField};
use std::collections::HashMap;

impl StructMember {
    pub fn add(&mut self, name: String
        , typ: Type) {
        /*
         * 该函数被调用之前, typ 已经被计算好(如果是第三方包,
         * 会先被加载到内存, 然后将引用地址写入到 Type::Structure g)
         * */
        match typ.typ_clone() {
            TypeValue::Structure(s) => {
                /*
                 * 是一个结构体
                 *  1. 将自身写入
                 *  2. 将结构体中的字段展开
                 * */
                /*
                 * 将自身写入
                 * */
                self.add_field(name.clone(), typ);
                /*
                 * 将结构体展开
                 * */
                let struct_define = s.struct_obj.as_ref();
                let members = match struct_define.member_ref() {
                    Some(ms) => {
                        ms.members_ref()
                    },
                    None => {
                        return;
                    }
                };
                for (sub_name, field) in members.iter() {
                    let n = format!("{}.{}", name, sub_name);
                    self.members.insert(n
                        , field.clone_with_index_plus(self.index));
                }
                self.index += members.len();
            },
            _ => {
                /*
                 * 非嵌套类型 => 直接写入
                 * */
                self.add_field(name, typ);
            }
        }
    }

    fn add_field(&mut self, name: String
        , typ: Type) {
        let field = StructField {
            index: self.index,
            typ: typ
        };
        self.add_field_with_field(name, field);
    }

    fn add_field_with_field(&mut self, name: String
        , field: StructField) {
        self.members.insert(name, field);
        self.index += 1;
    }

    pub fn print_members(&self) {
        for item in self.members.iter() {
            println!("{:?}", item);
        }
    }

    pub fn new() -> Self {
        Self {
            index: 0,
            members: HashMap::new()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::primeval::PrimevalType;
    use crate::{TypeAttrubute, Primeval
        , Structure, StructObject
        , StructDefine};

    #[test]
    fn member_add_test() {
        let mut root_m = StructMember::new();
        let mut cert_m = StructMember::new();
        {
            /*
             * add cert
             * */
            cert_m.add(String::from("cert_name"), &Type::new(
                    TypeValue::Primeval(Primeval::new(PrimevalType::Str))
                , TypeAttrubute::Empty));
            cert_m.add(String::from("cert_no"), &Type::new(
                    TypeValue::Primeval(Primeval::new(PrimevalType::Uint64))
                    , TypeAttrubute::Empty));
        }
        let cert_define = StructDefine::new_with_all(String::from("user_info")
            , Some(cert_m));
        /*
         * add root
         * */
        root_m.add(String::from("user_name"), &Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Str))
            , TypeAttrubute::Empty));
        root_m.add(String::from("user_age"), &Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Uint8))
                , TypeAttrubute::Empty));
        root_m.add(String::from("cert"), &Type::new(
                TypeValue::Structure(Structure::new(StructObject::from_ref(&cert_define)))
                    , TypeAttrubute::Empty));
        root_m.add(String::from("user_no"), &Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Str))
            , TypeAttrubute::Empty));
        root_m.print_members();
    }
}


use crate::{Type, TypeValue, TypeAttrubute
    , AddressType};
use super::{StructMember, StructField};
use std::collections::HashMap;

impl StructMember {
    pub fn add(&mut self, name: String
        , typ: Type, typ_attr: TypeAttrubute
        , addr_type: AddressType) {
        // println!("add {}, typ: {:?}", name, typ);
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
                self.add_field(name.clone(), typ, typ_attr, addr_type);
                /*
                 * 将结构体展开
                 * */
                let struct_define = s.struct_obj.pop();
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
                s.struct_obj_ref().push(struct_define);
            },
            _ => {
                /*
                 * 非嵌套类型 => 直接写入
                 * */
                self.add_field(name, typ, typ_attr, addr_type);
            }
        }
    }

    fn add_field(&mut self, name: String
        , typ: Type, typ_attr: TypeAttrubute
        , addr_type: AddressType) {
        let field = StructField {
            index: self.index,
            typ: typ,
            typ_attr: typ_attr,
            addr_type: addr_type
        };
        self.add_field_with_field(name, field);
    }

    fn add_field_with_field(&mut self, name: String
        , field: StructField) {
        self.members.insert(name, field);
        self.index += 1;
    }

    pub fn find_field(&self, name: &str) -> Option<&StructField> {
        self.members.get(name)
    }

    pub fn length(&self) -> usize {
        self.members.len()
    }

    pub fn print_members(&self) {
        for item in self.members.iter() {
            println!("{:?}", item);
        }
    }

    pub fn print_members_struct_fields(&self) {
        use crate::TypeValue;
        for (name, field) in self.members.iter() {
            match field.typ_ref().typ_ref() {
                TypeValue::Structure(s) => {
                    let struct_obj = s.struct_obj_ref();
                    let v = struct_obj.pop();
                    println!("{:?}", v);
                    struct_obj.push(v);
                },
                _ => {}
            }
        }
    }

    pub fn index_field_mapping(&self) -> HashMap<usize, &StructField>{
        let mut ms = HashMap::new();
        for (_, v) in self.members.iter() {
            ms.insert(v.index_clone() as usize, v);
        }
        ms
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
    use libcommon::ptr::HeapPtr;
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
            cert_m.add(String::from("cert_name"), Type::new(
                    TypeValue::Primeval(Primeval::new(PrimevalType::Str))
                , TypeAttrubute::Empty), TypeAttrubute::Ref
                , AddressType::Static);
            cert_m.add(String::from("cert_no"), Type::new(
                    TypeValue::Primeval(Primeval::new(PrimevalType::Uint64))
                    , TypeAttrubute::Empty), TypeAttrubute::Move
                    , AddressType::Stack);
        }
        let cert_define = StructDefine::new_with_all(String::from("user_info")
            , Some(cert_m));
        /*
         * add root
         * */
        root_m.add(String::from("user_name"), Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Str))
                , TypeAttrubute::Empty), TypeAttrubute::Ref
                , AddressType::Static);
        root_m.add(String::from("user_age"), Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Uint8))
                , TypeAttrubute::Empty), TypeAttrubute::Move
                , AddressType::Stack);
        root_m.add(String::from("cert"), Type::new(
                TypeValue::Structure(Structure::new(StructObject::new(HeapPtr::alloc(cert_define))))
                    , TypeAttrubute::Empty), TypeAttrubute::Move
                    , AddressType::Stack);
        root_m.add(String::from("user_no"), Type::new(
                TypeValue::Primeval(Primeval::new(PrimevalType::Str))
                , TypeAttrubute::Empty), TypeAttrubute::Ref
                , AddressType::Static);
        root_m.print_members();
    }
}


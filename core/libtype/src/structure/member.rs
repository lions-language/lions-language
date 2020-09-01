use crate::{Type, TypeValue};
use super::{StructMember, StructField};
use std::collections::HashMap;

impl StructMember {
    /*
     * 需要一种数据结构, 满足如下条件
     *  1. 保证写入的顺序永远一致
     *  2. 读取效率高
     * */
    pub fn add(&mut self, name: String
        , typ: &Type) {
        /*
         * 该函数被调用之前, typ 已经被计算好(如果是第三方包,
         * 会先被加载到内存, 然后将引用地址写入到 Type::Structure g)
         * */
        match typ.typ_ref() {
            TypeValue::Structure(s) => {
                /*
                 * 是一个结构体
                 *  1. 将自身写入
                 *  2. 将结构体中的字段展开
                 * */
                /*
                 * 将自身写入
                 * */
                self.add_field(name);
                /*
                 * 将结构体展开
                 * */
                let struct_define = s.struct_obj.as_ref();
                struct_define.member_ref();
            },
            _ => {
                /*
                 * 非嵌套类型 => 直接写入
                 * */
                self.add_field(name);
            }
        }
    }

    fn add_field(&mut self, name: String) {
        let field = StructField {
            index: self.index
        };
        self.members.insert(name, field);
        self.index += 1;
    }

    pub fn new() -> Self {
        Self {
            index: 0,
            members: HashMap::new()
        }
    }
}


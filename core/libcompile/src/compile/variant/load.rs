use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{LoadVariantContext};
use libtype::function::{AddFunctionContext};
use libtype::structure::{StructDefine};
use libtype::{PackageType, PackageTypeValue
    , AddressType, TypeAttrubute, TypeValue
    , AddressKey, AddressValue};
use libresult::DescResult;
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, AddressValueExpand};
use crate::compile::value_buffer::{ValueBufferItemContext};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_load_variant(&mut self, context: LoadVariantContext) -> DescResult {
        if self.scope_context.current_unchecked().get_is_point_access() {
            self.handle_load_variant_with_point_access(context)
        } else {
            self.handle_load_variant_no_point_access(context)
        }
    }

    fn handle_load_variant_with_point_access(&mut self, context: LoadVariantContext) -> DescResult {
        let (first, _, typ_attr, lengthen_offset) = context.fields_move();
        let first_data = first.token_data().expect("should not happend");
        let first = extract_token_data!(first_data, Id);
        let value_item = match self.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(e) => {
                return e;
            }
        };
        // println!("{:?}", &value);
        let value_typ = value_item.typ_ref().clone();
        let value_typ_attr = value_item.typ_attr_clone();
        let value_addr = value_item.addr_ref().addr_clone();
        let value_context = value_item.context_clone();
        match value_typ.typ_ref() {
            TypeValue::Structure(s) => {
                let struct_define = s.struct_obj_ref().pop();
                let member = match struct_define.member_ref() {
                    Some(m) => m,
                    None => {
                        return DescResult::Error(
                            format!("not found {}, in {:?}", first, struct_define.name_ref()));
                    }
                };
                let field = match member.find_field(&first) {
                    Some(f) => f,
                    None => {
                        return DescResult::Error(
                            format!("not found {}, in {:?}", first, struct_define.name_ref()));
                    }
                };
                /*
                let at = if var_typ_attr.is_ref() {
                    var_typ_attr
                } else {
                    field.typ_attr_clone()
                };
                */
                // println!("{:?}", value_addr);
                let addr = Address::new(AddressValue::new(
                        field.addr_type_clone()
                        , AddressKey::new_with_all(
                            (value_addr.addr_ref().index_clone() as usize + field.index_clone() + 1)
                            as u64
                            , 0, 0, 0, field.length())));
                // println!("{:?}", addr);
                self.scope_context.push_with_addr_context_typattr_to_value_buffer(
                    field.typ_clone()
                    , addr
                    , value_context
                    , field.typ_attr_clone());
                // println!("{:?}", field);
                s.struct_obj_ref().push(struct_define);
            },
            _ => {
                return DescResult::Error(
                    format!("not found {}, in {:?}", first, value_typ));
            }
        }
        DescResult::Success
    }

    fn handle_load_variant_no_point_access(&mut self, context: LoadVariantContext) -> DescResult {
        /*
         * 1. 从作用域中递归查找变量名对应的地址
         * */
        let (first, _, typ_attr, lengthen_offset) = context.fields_move();
        let first_data = first.token_data().expect("should not happend");
        let first = extract_token_data!(first_data, Id);
        let (name, var) = match self.scope_context.find_variant(&first) {
            Some(v) => {
                v
            },
            None => {
                return DescResult::Error(
                    format!("var: {:?} is undefine or be moved", &first));
            }
        };
        /*
         * 1. 添加 value buffer 中
         *  因为 variant 中记录的就是实际存储数据的地址, 所以需要将 variant 中的 addr 存储到
         *  value_buffer 中
         * 2. 不需要生成指令
         *  因为变量只是一个标识, 找到实际存储数据的地址就可以方便之后的计算,
         *  所以只是在编译期进行推断使用的, 运行时不需要
         * */
        let buf_ctx = ValueBufferItemContext::Variant(
            RefPtr::from_ref(name));
        let (mut var_addr, var_typ, var_typ_attr, _) = var.fields_move();
        /*
         * 修改 var_addr
         * */
        // println!("{:?}", var_addr);
        *var_addr.addr_mut().addr_mut().lengthen_offset_mut() = lengthen_offset;
        /*
         * NOTE
         *  如果变量前面有 `&`, 那么就是 引用
         *  如果变量前面没有 `&`, 那么是否是 引用 决定于 被指向的数据
         *  (可能存在 var b = &1; var a = b; 那么 a 应该是引用, 而不是 移动)
         * */
        // println!("{:?}", var_addr);
        let at = if var_typ_attr.is_ref() {
            var_typ_attr
        } else {
            typ_attr
        };
        self.scope_context.push_with_addr_context_typattr_to_value_buffer(
            var_typ
            , var_addr, buf_ctx
            , at);
        DescResult::Success
    }
}

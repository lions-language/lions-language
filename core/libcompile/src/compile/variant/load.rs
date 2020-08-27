use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{LoadVariantContext};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , AddressType, TypeAttrubute};
use libresult::DescResult;
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, AddressValueExpand};
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_load_variant(&mut self, context: LoadVariantContext) -> DescResult {
        /*
         * 1. 从作用域中递归查找变量名对应的地址
         * */
        let (first, _, typ_attr) = context.fields_move();
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
        // println!("load var {:?}", name);
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
        // println!("{:?}, name: {}", &buf_ctx, name);
        let (mut var_addr, var_typ, var_typ_attr) = var.fields_move();
        // println!("{:?}", var_addr);
        // println!("{:?}", &var_typ_attr);
        // println!("{:?}: {:?}", name, &typ_attr);
        /*
         * NOTE
         *  如果变量前面有 `&`, 那么就是 引用
         *  如果变量前面没有 `&`, 那么是否是 引用 决定于 被指向的数据
         *  (可能存在 var b = &1; var a = b; 那么 a 应该是引用, 而不是 移动)
         * */
        let at = if var_typ_attr.is_ref() {
            var_typ_attr
        } else {
            typ_attr
        };
        // println!("{:?}, {:?}", name, at);
        // println!("{:?}, {:?}", name, var_addr);
        /*
                                        if let AddressType::ParamRef(_) =
                                            var_addr.addr_ref().typ_ref() {
                                            var_addr.addr_mut().addr_mut_with_scope_plus(1);
                                        };
                                        */
        self.scope_context.push_with_addr_context_typattr_to_value_buffer(
            var_typ
            , var_addr, buf_ctx
            , at);
        DescResult::Success
    }
}

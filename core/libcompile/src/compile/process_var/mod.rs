use libgrammar::token::{TokenValue, TokenData};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , AddressType, AddressValue
    , Type, TypeAttrubute};
use libgrammar::grammar::{VarStmtContext};
use crate::address::Address;
use crate::compile::{Compile, Compiler, VariantDefineContext};
use crate::compile::scope::vars::Variant;
use crate::compile::value_buffer::{ValueBufferItemContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_var_stmt_start(&mut self) {
    }

    pub fn handle_var_stmt_end(&mut self, context: VarStmtContext) {
        let is_exist_equal = *context.is_exist_equal_ref();
        /*
         * 1. 为变量在栈上分配一个空的地址 (如果存在`=`, 再改变该地址)
         * 2. 将变量写入到作用域中
         * */
         let name = extract_token_data!(
            context.id_token().token_data().expect("should not happend")
            , Id);
        let mut src_addr = AddressValue::new_invalid();
        let mut typ = Type::new_null();
        if is_exist_equal {
            /*
             * 存在 `=` (赋予初始值)
             *  1. 从栈顶获取表达式的计算结果
             *  2. 判断等号的右边的计算结果是否是变量, 如果是变量, 需要更新 vars 中对应的值为 Move
             *      读取变量的时候, 如果值为 Move, 需要报错
             * */
            let value = self.scope_context.take_top_from_value_buffer();
            // println!("{:?}", &value);
            typ = value.typ_ref().clone();
            if let TypeAttrubute::Move = typ.attr_ref() {
                match value.context_ref() {
                    ValueBufferItemContext::Variant(v) => {
                        let var_name = v.as_ref::<String>();
                        self.scope_context.remove_variant_unchecked(
                            value.addr_ref().addr_ref().addr_ref().scope_clone()
                            , var_name);
                    },
                    _ => {}
                }
            };
            src_addr = value.addr().addr();
        }
        /*
         * 将实际存储数据的地址存储到 Variant 对象中 (也就是 src_addr)
         * 不需要生成指令, 因为变量在编译期已经转换为了地址, 虚拟机不要管
         * */
        self.scope_context.add_variant(name
            , Variant::new_with_all(
                Address::new(src_addr), typ));
        /*
        let addr = self.scope_context.alloc_address(AddressType::Stack, 0);
        self.cb.variant_define(VariantDefineContext::new_with_all(
            addr.addr(), src_addr));
        */
    }
}

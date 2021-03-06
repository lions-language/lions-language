use libgrammar::token::{TokenValue, TokenType};
use libgrammar::grammar::{ConstStringContext};
use libtype::{AddressValue, AddressType
    , Type, TypeValue, Primeval};
use libtype::package::PackageStr;
use crate::compile::{Compile, Compiler, StaticContext
    , TokenValueExpand};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_const_string(&mut self, context: ConstStringContext) {
        let (value, typ_attr) = context.fields_move();
        // value.print_token_data();
        // println!("{:?}", &typ_attr);
        /*
         * TokenType 转换为 Type
         * */
        // let typ = value.to_type().clone();
        let typ = match value.token_type_clone() {
            TokenType::Const(t) => {
                Type::new(TypeValue::Primeval(Primeval::new(
                            t)), typ_attr.clone())
            },
            _ => {
                panic!("should not happend");
            }
        };
        /*
         * 在静态区分配一个地址, 并将数据写入到静态区
         * 该操作不会生成到指令中
         * */
        let static_addr = self.static_variant_dispatch.alloc(value.to_data());
        /*
         * 在当前作用域中分配一个地址, 提供给虚拟机进行绑定
         * */
        let addr = self.scope_context.alloc_address(AddressType::Static, 0, 0);
        /*
         * 将地址写入到编译期的计算栈中, 为之后的运算做准备
         * */
        /*
        self.scope_context.push_with_addr_typattr_to_value_buffer(typ.clone()
            , Address::new(AddressValue::new(AddressType::Static, static_addr.clone()))
            , typ_attr);
        */
        self.scope_context.push_with_addr_typattr_to_value_buffer(typ.clone()
            , addr.clone()
            , typ_attr);
        /*
         * 生成读取静态量的指令, 虚拟机接收到这个指令后, 在当前作用域中建立一个绑定关系
         * */
        let const_context = StaticContext::from_token_value(
            PackageStr::Itself, addr.addr(), static_addr);
        self.cb.const_string(const_context);
    }
}


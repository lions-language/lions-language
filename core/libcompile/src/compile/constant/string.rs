use libgrammar::token::{TokenValue};
use libtype::{AddressValue, AddressType};
use libtype::package::PackageStr;
use crate::compile::{Compile, Compiler, StaticContext
    , TokenValueExpand};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_const_string(&mut self, value: TokenValue) {
        /*
         * TokenType 转换为 Type
         * */
        let typ = value.to_type().clone();
        /*
         * 在静态区分配一个地址, 并将数据写入到静态区
         * 这句话不会生成到指令中
         * */
        let static_addr = self.static_variant_dispatch.alloc(value.to_data());
        /*
         * 在当前作用域中分配一个地址, 提供给虚拟机进行绑定
         * */
        let addr = self.scope_context.alloc_address(AddressType::Static);
        /*
         * 将地址写入到编译期的计算栈中, 为之后的运算做准备
         * */
        self.scope_context.push_with_addr_to_value_buffer(typ.clone()
            , Address::new(AddressValue::new(AddressType::Static, static_addr.clone())));
        /*
         * 生成读取静态量的指令, 虚拟机接收到这个指令后, 在当前作用域中建立一个绑定关系
         * */
        let const_context = StaticContext::from_token_value(
            PackageStr::Itself, addr.addr(), static_addr);
        self.cb.const_string(const_context);
    }
}


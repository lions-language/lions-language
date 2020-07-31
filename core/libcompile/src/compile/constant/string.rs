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
         * */
        let addr = self.static_variant_dispatch.alloc(value.to_data());
        /*
         * 将地址写入到编译期的计算栈中, 为之后的运算做准备
         * */
        self.value_buffer.push_with_addr(typ.clone()
            , Address::new(AddressValue::new(AddressType::Static, addr.clone())));
        /*
         * 生成读取静态量的指令, 虚拟机接收到这个指令后, 将地址写入到计算栈中
         * */
        let const_context = StaticContext::from_token_value(
            PackageStr::Itself, typ, addr);
        self.cb.const_string(const_context);
    }
}


use libgrammar::token::{TokenValue};
use libtype::package::PackageStr;
use libtype::{AddressValue
    , AddressType};
use crate::address::{Address};
use crate::compile::{Compile, Compiler
    , LoadStackContext, TokenValueExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn const_number(&mut self, value: TokenValue) {
        /*
         * TokenType 转换为 Type
         * */
        /*
         * TODO: Type 中无法知道是 Move / Ref / Ptr ...
         *  1. 将 Type 中的 TypeAttrubute 去掉
         *  2. 将 这些属性放在 Param (函数参数) 中
         * */
        let typ = value.to_type().clone();
        /*
         * 在栈上分配一个地址
         * */
        let addr = self.scope_context.alloc_address(AddressType::Stack);
        /*
         * 将地址写入到编译期的计算栈中, 为之后的运算做准备
         * */
        self.scope_context.push_with_addr_to_value_buffer(typ.clone()
            , addr.clone());
        /*
         * 生成读取静态量的指令, 虚拟机接收到这个指令后, 将地址写入到计算栈中
         * */
        let context = LoadStackContext::new(
            addr.addr(), value.to_data());
        self.cb.load_stack(context);
    }
}


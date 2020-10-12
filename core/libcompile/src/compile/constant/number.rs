use libgrammar::grammar::{ConstNumberContext};
use libgrammar::token::{TokenType, TokenValue, TokenData};
use libtype::package::PackageStr;
use libtype::{AddressValue
    , AddressType, Type
    , TypeValue, Primeval};
use crate::address::{Address};
use crate::compile::{Compile, Compiler
    , LoadStackContext, TokenValueExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn const_number(&mut self, context: ConstNumberContext) {
        let (value, typ_attr) = context.fields_move();
        /*
         * TokenType 转换为 Type
         * */
        /*
         * TODO: Type 中无法知道是 Move / Ref / Ptr ...
         *  1. 将 Type 中的 TypeAttrubute 去掉
         *  2. 将 这些属性放在 Param (函数参数) 中
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
         * 在栈上分配一个地址
         * */
        let addr = self.scope_context.alloc_address(AddressType::Stack, 0, 0);
        /*
         * 将地址写入到编译期的计算栈中, 为之后的运算做准备
         * */
        // println!("--- {:?}", &typ_attr);
        self.scope_context.push_with_addr_typattr_to_value_buffer(typ.clone()
            , addr.clone(), typ_attr);
        /*
         * 生成读取静态量的指令, 虚拟机接收到这个指令后, 将地址写入到计算栈中
         * */
        let context = LoadStackContext::new_with_all(
            addr.addr(), value.to_data());
        self.cb.load_stack(context);
    }
}


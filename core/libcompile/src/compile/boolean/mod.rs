// use libgrammar::token::{TokenData};
use libgrammar::grammar::{ConstBooleanContext};
use libtype::{Type, TypeValue, Primeval
    , AddressType
    , primeval::PrimevalType};
use crate::compile::{Compile, Compiler, TokenValueExpand
    , LoadStackContext};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_const_boolean(&mut self, context: ConstBooleanContext) {
        let (value, typ_attr) = context.fields_move();
        let typ = Type::new(TypeValue::Primeval(Primeval::new(
                    PrimevalType::Boolean)), typ_attr.clone());
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


use libtype::instruction::{
    CallFunction
    , AddRefParamAddr};
use libcommon::optcode::{OptCode};
use libcommon::address::{FunctionAddrValue, FunctionAddress};
use libcompile::define_stream::{DefineStream};
use liblink::define::{LinkDefine};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn call_function(&mut self, value: CallFunction
        , current_pos: &usize, block_length: &usize) {
        /*
         * 函数调用之前, 先将函数调用完成之后的指令位置记录下来
         *  函数调用指令 + leave scope 指令 => 在 current pos 的基础上加2
         * */
        match self.thread_context.current_mut_unchecked().scope_context_mut()
            .last_one_mut() {
            Some(scope) => {
                scope.set_after_func_call_addr(
                    FunctionAddrValue::new(current_pos.clone() + 2
                        , block_length.clone()));
            },
            None => {
            }
        }
        /*
         * 将函数返回值的地址写入到作用域中, 之后的 return 语句将会绑定这个地址
         * */
        // println!("{:?}", value.return_data_ref().addr_value_ref());
        self.thread_context.current_mut_unchecked().scope_context_mut()
            .last_one_mut_unchecked().set_func_call_return_addr(
                value.return_data_ref().addr_value_ref().clone());
        /*
         * 1. 在 当前作用域中 查找 param_addrs 中指定的参数地址对应的数据
         * 2. 创建作用域
         * 3. 根据第一步的值, 在调用函数内部的指令之前先将函数调用创建的作用域的参数位置进行填充
         * */
        /*
         * 创建作用域
         * */
        // self.thread_context.enter_thread_scope();
        let ld = self.link_define.clone();
        let ld = ld.as_ref::<LinkDefine>();
        match value.define_addr_ref() {
            FunctionAddress::Define(v) => {
                let mut block = ld.read(v);
                /*
                */
                while let Some(ins) = block.get_next() {
                    self.execute(ins.clone(), block.current_pos_ref(), block.block_length_ref());
                }
                /*
                for ins in block {
                    // self.execute(ins, block.current_pos_ref(), block.block_length_ref());
                    self.execute(ins, &0, &0);
                }
                */
            },
            _ => {
                unimplemented!();
            }
        }
        /*
        /*
         * TODO: 绑定地址
         * 1. 编译期在遇到 return 的时候, 会让虚拟机将return指向的数据地址存储在当前作用域中
         *  这里需要将当前作用域中的 数据地址 和 CallFunction 中的 return_addr 进行绑定
         * */
        if value.return_data_ref().is_alloc_ref().clone() {
            let data_addr = self.thread_context.current_unchecked().get_result_data_addr().clone();
            // println!("{:?}, {:?}", value.return_data_ref().addr_value_ref().addr_ref(), &data_addr);
            self.thread_context.current_mut_unchecked().add_bind(
                value.return_data_ref().addr_value_ref().addr_clone()
                , data_addr.clone());
        }
        */
        /*
         * 离开作用域
         * */
        // self.thread_context.leave_thread_scope();
    }

    pub fn add_ref_param_addr(&mut self, value: AddRefParamAddr) {
        /*
         * 将地址写入到 ref param addr mapping 中
         * */
        let (addr, dst_addr) = value.fields_move();
        self.thread_context.current_mut_unchecked().add_ref_param_addr_bind(
            addr, dst_addr);
    }
}


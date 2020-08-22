use libtype::instruction::{
    CallFunction
    , PushParamRef};
use libcommon::optcode::{OptCode};
use libcommon::address::{FunctionAddrValue, FunctionAddress};
use libcompile::define_stream::{DefineStream};
use liblink::define::{LinkDefine};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn call_function(&mut self, value: CallFunction) {
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
                let iter = ld.read(v);
                for ins in iter {
                    self.execute(ins);
                }
            },
            _ => {
                unimplemented!();
            }
        }
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
        /*
         * 离开作用域
         * */
        // self.thread_context.leave_thread_scope();
    }

    pub fn push_param_ref(&mut self, value: PushParamRef) {
        /*
         * 获取地址对应的数据地址
         * */
        let data_addr = self.thread_context.current_unchecked().get_data_addr_unchecked(
            value.addr_ref().addr_ref()).clone();
        self.thread_context.current_mut_unchecked().push_current_param_ref(data_addr);
    }
}


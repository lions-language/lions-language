use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{OwnershipMove, RemoveOwnership};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn ownership_move(&mut self, value: OwnershipMove) {
        // println!("{:?}", &value);
        // println!("ownership move");
        /*
         * 1. 将 dst_addr 绑定到 src_addr 指向的数据地址
         * 2. 将 src_addr 指向的数据地址 解绑
         * */
        /*
        self.thread_context.current_mut_unchecked().print_current_addr_mapping();
        self.thread_context.current_mut_unchecked().print_last_n_addr_mapping(1);
        self.thread_context.current_mut_unchecked().print_stack_datas();
        */
        let (dst_addr, src_addr) = value.fields_move();
        let src_data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&src_addr).addr_value_clone();
        // println!("--- {:?}", src_data_addr);
        // println!("{:?}", dst_addr);
        /*
         * 绑定
         * */
        self.thread_context.current_mut_unchecked()
            .add_bind(dst_addr
                , src_data_addr);
        /*
         * 解绑
         * */
        self.thread_context.current_mut_unchecked()
            .remove_bind(src_addr.addr());
        /*
        self.thread_context.current_mut_unchecked().print_current_addr_mapping();
        self.thread_context.current_mut_unchecked().print_last_n_addr_mapping(1);
        self.thread_context.current_mut_unchecked().print_stack_datas();
        */
    }

    pub fn remove_ownership(&mut self, value: RemoveOwnership) {
        // println!("remove ownership");
        self.thread_context.current_mut_unchecked()
            .remove_bind(value.addr());
    }
}

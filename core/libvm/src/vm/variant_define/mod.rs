use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{VariantDefine};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn variant_define(&mut self, value: VariantDefine) {
        // println!("{:?}", &value);
        /*
         * 1. 将 dst_addr 绑定到 src_addr 指向的数据地址
         * 2. 将 src_addr 指向的数据地址 解绑
         * */
        let (dst_addr, src_addr) = value.fields_move();
        let src_data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&src_addr).get_clone();
        /*
         * 绑定
         * */
        self.thread_context.current_mut_unchecked()
            .add_bind(dst_addr.addr_clone()
                , src_data_addr);
        /*
         * 解绑
         * */
        self.thread_context.current_mut_unchecked()
            .remove_bind(src_addr.addr());
        self.thread_context.current_mut_unchecked().print_addr_mapping(dst_addr.addr());
        self.thread_context.current_mut_unchecked().print_stack_datas();
    }
}
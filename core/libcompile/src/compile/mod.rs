use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libhosttype::primeval::{PrimevalControl, PrimevalMethod};
use libhosttype::primeval::finder_map::hash;

pub struct Compile {
    primeval_control: PrimevalControl<hash::Finder>,
    value_buffer: value_buffer::ValueBuffer,
    module_stack: module_stack::ModuleStack
}

impl Grammar for Compile {
    fn express_const_number(&mut self, value: TokenValue) {
        self.value_buffer.push(value);
    }

    fn operator_plus(&mut self, value: TokenValue) {
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let left = self.value_buffer.top_n_with_panic(2);
        let left_type_str = self.tokenvalue_type_str(left);
        let right = self.value_buffer.top_n_with_panic(1);
        let right_type_str = self.tokenvalue_type_str(right);
        let func_key = self.splice_binary_operator_funckey(
            left_type_str, "+", right_type_str);
        let current_module = self.module_stack.current();
        // self.primeval_control
    }
}

mod module_stack;
mod value_buffer;
mod aide;

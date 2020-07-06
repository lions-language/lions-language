use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};

pub struct Compile {
}

impl Grammar for Compile {
    fn express_const_number(&mut self, value: TokenValue) {
    }

    fn operator_plus(&mut self, value: TokenValue) {
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
    }
}

use crate::grammar::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn typesof_calc(&mut self) {
        /*
         * 解析类型
         * 类型属性(ptr, const); 类型名称(可能有 模块前缀 ::)
         * 直接调用 Grammar 方法, 不用返回值
         * */
    }
}

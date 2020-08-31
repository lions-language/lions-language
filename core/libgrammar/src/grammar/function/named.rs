use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenValue};
use crate::grammar::{FunctionDefineContext};
  
impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_named(&mut self) {
        /*
         * 含有名称 function
         * 命名函数
         * */
        let next = self.take_next_one();
        let mut context = FunctionDefineContext::new_with_all(false);
        self.grammar_context().cb.function_named_stmt(next.token_value());
        self.function_parse_param_list(&mut context);
        self.function_parse_return();
        self.function_parse_block(&mut context);
    }
}


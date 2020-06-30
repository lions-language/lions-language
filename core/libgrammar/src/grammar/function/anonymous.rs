use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
  
impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_anonymous(&mut self) {
        /*
         * 匿名 function
         * */
    }
}


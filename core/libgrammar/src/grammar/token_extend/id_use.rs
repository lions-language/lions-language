use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, Grammar};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    /*
     * 查看 id 后面是不是 ::
     * */
}


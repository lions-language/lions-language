use libtype::{TypeAttrubute};
use libtype::function::{FunctionParamLengthenAttr};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , FunctionDefineParamContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

enum FunctionType {
    Unknown,
    Named,
    Anonymous,
    ObjectMethod,
    StructMethod
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn interface_process(&mut self) {
        /*
         * 跳过 interface 关键字
         * */
        self.skip_next_one();
    }
}

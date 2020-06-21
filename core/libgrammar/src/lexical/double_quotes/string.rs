use crate::token::{Token, TokenOperType, TokenAttrubute, TokenContext};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::Grammar;

pub struct StringToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for StringToken {
    fn context(&self) -> &TokenContext {
        return &self.context;
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*id_token_attrubute
    }
}

impl StringToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}



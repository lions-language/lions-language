use crate::token::{Token, TokenOperType, TokenAttrubute, TokenContext};
use crate::lexical::CallbackReturnStatus;

pub struct NumberToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for NumberToken {
    fn context(&self) -> &TokenContext {
        return &self.context;
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*id_token_attrubute
    }
}

impl NumberToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}



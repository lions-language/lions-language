use crate::token::{Token, TokenOperType, TokenAttrubute, TokenContext};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::Grammar;

pub struct IdToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for IdToken {
    fn context_ref(&self) -> &TokenContext {
        return &self.context;
    }

    fn context(self) -> TokenContext {
        self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*id_token_attrubute
    }
}

impl IdToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}



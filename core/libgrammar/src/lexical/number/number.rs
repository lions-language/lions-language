use libcommon::token::{Token, TokenOperType, TokenAttrubute, TokenContext};

pub struct NumberToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl Token for NumberToken {
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



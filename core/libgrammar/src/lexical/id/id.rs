use libcommon::token::{Token, TokenOperType, TokenAttrubute, TokenContext};

pub struct IdToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl Token for IdToken {
    fn context(&self) -> &TokenContext {
        return &self.context;
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



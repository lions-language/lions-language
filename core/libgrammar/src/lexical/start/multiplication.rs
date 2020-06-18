use libcommon::token::{TokenContext, Token, TokenAttrubute, TokenOperType};

pub struct MultiplicationToken {
    context: TokenContext
}

lazy_static!{
    static ref multiplication_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operator
    };
}

impl Token for MultiplicationToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*multiplication_token_attrubute
    }
}

impl MultiplicationToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


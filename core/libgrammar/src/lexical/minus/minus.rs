use libcommon::token::{TokenContext, Token, TokenAttrubute, TokenOperType};

lazy_static!{
    static ref minus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct MinusToken {
    context: TokenContext
}

impl Token for MinusToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*minus_token_attrubute
    }
}

impl MinusToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


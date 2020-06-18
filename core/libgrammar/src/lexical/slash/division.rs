use libcommon::token::{TokenContext, Token, TokenAttrubute, TokenOperType};

pub struct DivisionToken {
    context: TokenContext
}

lazy_static!{
    static ref division_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operator
    };
}

impl Token for DivisionToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*division_token_attrubute
    }
}

impl DivisionToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


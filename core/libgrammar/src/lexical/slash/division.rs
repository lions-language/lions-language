use libcommon::token::{TokenContext, Token};

pub struct DivisionToken {
    context: TokenContext
}

impl Token for DivisionToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl DivisionToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


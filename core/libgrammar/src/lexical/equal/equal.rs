use libcommon::token::{TokenContext, Token};

pub struct EqualToken {
    context: TokenContext
}

impl Token for EqualToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl EqualToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


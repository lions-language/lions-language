use libcommon::token::{TokenContext, Token};

pub struct MultiplicationToken {
    context: TokenContext
}

impl Token for MultiplicationToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl MultiplicationToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


use libcommon::token::{TokenContext, Token};

pub struct LeftParentheseToken {
    context: TokenContext
}

impl Token for LeftParentheseToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl LeftParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


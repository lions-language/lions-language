use libcommon::token::{TokenContext, Token};

pub struct RightParentheseToken {
    context: TokenContext
}

impl Token for RightParentheseToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl RightParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


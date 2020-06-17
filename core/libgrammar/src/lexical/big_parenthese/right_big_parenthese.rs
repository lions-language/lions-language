use libcommon::token::{TokenContext, Token};

pub struct RightBigParentheseToken {
    context: TokenContext
}

impl Token for RightBigParentheseToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl RightBigParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


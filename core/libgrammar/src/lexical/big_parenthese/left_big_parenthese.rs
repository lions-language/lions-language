use libcommon::token::{TokenContext, Token};

pub struct LeftBigParentheseToken {
    context: TokenContext
}

impl Token for LeftBigParentheseToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl LeftBigParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


use libcommon::token::{TokenContext, Token};

pub struct PlusToken {
    context: TokenContext
}

impl Token for PlusToken {
    fn nup(&self, context: &TokenContext) {
    }

    fn led(&self, context: &TokenContext) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl PlusToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


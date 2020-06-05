use libcommon::token::{TokenContext, Token};

struct PlusToken {
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


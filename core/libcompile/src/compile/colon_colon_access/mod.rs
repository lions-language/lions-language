use libgrammar::grammar::{EnterColonColonAccessContext};
use crate::compile::{Compile, Compiler};
use crate::compile::scope::{ColonColonAccess};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_enter_colon_colon_access(&mut self, context: EnterColonColonAccessContext) {
        let prefix_name = context.fields_move();
        self.scope_context.current_mut_unchecked()
            .enter_colon_colon_access(ColonColonAccess::new_with_all(prefix_name));
    }

    pub fn process_leave_colon_colon_access(&mut self) {
        self.scope_context.current_mut_unchecked()
            .leave_colon_colon_access();
    }
}


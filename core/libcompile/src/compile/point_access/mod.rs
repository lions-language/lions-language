use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_enter_point_access(&mut self) {
        self.scope_context.current_mut_unchecked()
            .set_is_point_access(true);
    }

    pub fn process_leave_point_access(&mut self) {
        self.scope_context.current_mut_unchecked()
            .set_is_point_access(false);
    }
}


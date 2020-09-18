use crate::compile::{Compile, Compiler};
use crate::compile::scope::{PointAccess};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_enter_point_access(&mut self) {
        let value = self.scope_context.top_n_with_panic_from_value_buffer(1);
        let typ = value.typ_clone();
        let typ_attr = value.typ_attr_clone();
        let addr_value = value.addr_ref().addr_clone();
        self.scope_context.current_mut_unchecked()
            .enter_point_access(PointAccess::new_with_all(
                    typ, typ_attr, addr_value));
    }

    pub fn process_leave_point_access(&mut self) {
        self.scope_context.current_mut_unchecked()
            .leave_point_access();
    }
}


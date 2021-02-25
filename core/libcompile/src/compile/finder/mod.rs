use libresult::{DescResult};
use libgrammar::grammar::{FindInterfaceContext
    , FindInterfacePrefixContext
    , FindInterfaceEndContext};
use libgrammar::token::{TokenData};
use libcommon::consts::{ImportPrefixType};
use libcommon::ptr::{HeapPtr};
use std::path::Path;
use crate::compile::{Compile, Compiler, FileType};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_find_interface_prefix(&mut self, prefix_context: FindInterfacePrefixContext
                                         , context: &mut FindInterfaceContext) -> DescResult {
        if context.context_ref().is_null() {
            let id = extract_token_data!(prefix_context.value().token_data_unchecked(), Id);
            *context.context_mut() = HeapPtr::alloc(id);
        } else {
            unreachable!("prefix be called only once");
        }
        DescResult::Success
    }

    pub fn process_find_interface_end(&mut self, end_context: FindInterfaceEndContext
                                      , context: &mut FindInterfaceContext) -> DescResult {
        if context.context_ref().is_null() {
            /*
             * 无前缀
             * */
            let module_str = self.module_stack.current().name_ref();
        } else {
            /*
             * 存在前缀
             * */
            let module_prefix = context.context_mut().pop::<String>();
            let (module_str, package_str) = match self.imports_mapping.get_clone(&module_prefix) {
                Some(v) => {
                    let (ms, ps) = v.fields_move();
                    (Some(ms), ps)
                },
                None => {
                    return DescResult::Error(
                        format!("{} is not found", module_prefix));
                }
            };
        }
        DescResult::Success
    }
}


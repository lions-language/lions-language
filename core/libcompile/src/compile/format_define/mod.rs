use libresult::DescResult;
use libgrammar::grammar::{FormatDefine};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_format_define(&mut self, format_define: FormatDefine) {
        let (prefix, name) = format_define.fields_move();
        /*
         * 可能是 interface, 也可能是 struct, 还可能是 enum
         * */
        match prefix {
            Some(p) => {
            },
            None => {
            }
        }
    }
}


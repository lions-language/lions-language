use libresult::DescResult;
use libgrammar::grammar::{EnumDefineStartContext
    , EnumDefineItemContext, EnumDefineEndContext};
use libtype::enumerate::{EnumerateDefine, EnumerateItem};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_enum_define_start(&mut self
        , context: EnumDefineStartContext, define: &mut EnumerateDefine) -> DescResult {
        *define.name_mut() = context.name();
        DescResult::Success
    }

    pub fn process_enum_define_item(&mut self
        , context: EnumDefineItemContext, define: &mut EnumerateDefine) -> DescResult {
        let (name, format_define) = context.fields_move();
        match define.items_mut() {
            Some(item) => {
                let typ = match format_define {
                    Some(fd) => {
                        get_typ_from_format_define(format_define)
                    },
                    None => {
                        None
                    }
                };
                item.push(EnumerateItem:new_with_all(name, typ));
            },
            None => {
            }
        }
        DescResult::Success
    }

    pub fn process_enum_define_end(&mut self
        , context: EnumDefineEndContext, define: &mut EnumerateDefine) -> DescResult {
        DescResult::Success
    }
}

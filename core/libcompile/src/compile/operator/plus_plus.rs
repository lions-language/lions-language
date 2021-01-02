use libresult::*;
use libtype::{TypeAttrubute};
use libtype::package::PackageStr;
use libgrammar::token::TokenValue;
use libgrammar::grammar::{PrefixPlusPlusContext
    , DescContext};
use libtype::function::{FunctionDefine
        , FunctionStatement};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn prefix_plus_plus(&mut self, context: PrefixPlusPlusContext) -> DescResult {
        use libtype::function::consts;
        let (_, symbol_count) = context.fields_move();
        let value = self.scope_context.top_n_with_panic_from_value_buffer(1);
        let value_typ = value.typ_clone();
        let value_typ_attr = value.typ_attr_ref();
        let mut func_define = FunctionDefine::new_invalid_addr();
        let mut func_statement: Option<FunctionStatement> = None;
        let param_typs = vec![(value_typ.clone(), value_typ_attr.clone())];
        let (exists, func_str) = 
            match self.function_is_exist(consts::OPERATOR_PREFIX_PLUS_PLUS_FUNCTION_NAME
            , Some(&value_typ), value.package_str_clone(), &None
            , param_typs, &mut func_statement, &mut func_define) {
            Ok(r) => r,
            Err(err) => {
                return err;
            }
        };
        if !exists {
            return DescResult::Error(
                format!("{} is undefine", func_str));
        }
        self.call_function(func_statement, func_define, PackageStr::Empty
            , DescContext::new(TypeAttrubute::Ref))
    }
}


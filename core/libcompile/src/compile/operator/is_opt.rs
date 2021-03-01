use libresult::*;
use libtype::package::PackageStr;
use libgrammar::token::TokenValue;
use libgrammar::grammar::{OperatorIsContext};
use libtype::function::{FunctionDefine
        , FunctionStatement};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn operator_is(&mut self, context: OperatorIsContext) -> DescResult {
        use libtype::function::consts;
        let (_, desc_ctx) = context.fields_move();
        let right = self.scope_context.top_n_with_panic_from_value_buffer(1);
        let right_typ = right.typ_ref();
        let right_typ_attr = right.typ_attr_ref();
        let left = self.scope_context.top_n_with_panic_from_value_buffer(2);
        let left_typ = left.typ_clone();
        let left_typ_attr = left.typ_attr_ref();
        /*
        let (right_typ, right_addr, right_typ_attr, right_package_type, right_package_str, right_context)
            = take_value_top!(self, right_expr_value).fields_move();
        let (left_typ, left_addr, left_typ_attr, left_package_type, left_package_str, left_context)
            = take_value_top!(self, left_expr_value).fields_move();
        */
        let mut func_define = FunctionDefine::new_invalid_addr();
        let mut func_statement: Option<FunctionStatement> = None;
        let param_typs = vec![(left_typ.clone(), left_typ_attr.clone())
            , (right_typ.clone(), right_typ_attr.clone())];
        let (exists, func_str) = 
            match self.function_is_exist(consts::OPERATOR_EQUAL_EQUAL_FUNCTION_NAME
            , Some(&left_typ), left.package_str_clone(), &None
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
        let param_len = func_statement.as_ref().unwrap().get_func_param_len();
        /*
        self.call_function(func_statement, func_define, PackageStr::Empty
            , desc_ctx, param_len)
        */
        DescResult::Success
    }
}


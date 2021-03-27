use libresult::*;
use libtype::package::PackageStr;
use libgrammar::token::TokenValue;
use libgrammar::grammar::{OperatorTwoPointContext};
use libtype::function::{FunctionDefine
        , FunctionStatement};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn operator_two_point(&mut self, context: OperatorTwoPointContext) -> DescResult {
        use libtype::function::consts;
        let (_, desc_ctx) = context.fields_move();
        let right = self.scope_context.top_n_with_panic_from_value_buffer(1);
        let right_typ = right.typ_ref();
        let right_typ_attr = right.typ_attr_ref();
        let left = self.scope_context.top_n_with_panic_from_value_buffer(2);
        let left_typ = left.typ_clone();
        let left_typ_attr = left.typ_attr_ref();
        let mut func_define = FunctionDefine::new_invalid_addr();
        let mut func_statement: Option<FunctionStatement> = None;
        let param_typs = vec![(left_typ.clone(), left_typ_attr.clone())
            , (right_typ.clone(), right_typ_attr.clone())];
        let (left_module_str, left_package_str) = left.import_item_clone().fields_move();
        let (exists, func_str) = 
            match self.function_is_exist(consts::OPERATOR_TWO_POINT_FUNCTION_NAME
            , Some(&left_typ), left_package_str, &Some(left_module_str)
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
        self.call_function(func_statement, func_define, PackageStr::Empty
            , desc_ctx, param_len)
    }
}


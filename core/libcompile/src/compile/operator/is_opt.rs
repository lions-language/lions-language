use libresult::*;
use libtype::package::PackageStr;
use libgrammar::token::TokenValue;
use libgrammar::grammar::{OperatorIsContext};
use libtype::function::{FunctionDefine
        , FunctionStatement};
use libtype::{TypeValue, Interface};
use libtype::interface::InterfaceDefine;
use crate::compile::{Compile, Compiler};
use crate::compile::value_buffer::{ValueBufferItem};

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
         * 先判断right是否是interface
         * */
        match right_typ.typ_ref() {
            TypeValue::Interface(define) => {
                return self.is_interface_process(define.clone());
            },
            _ => {
            }
        }
        /*
         * 如果不是以上情况, 就查找函数
         * */
        let mut func_define = FunctionDefine::new_invalid_addr();
        let mut func_statement: Option<FunctionStatement> = None;
        let param_typs = vec![(left_typ.clone(), left_typ_attr.clone())
            , (right_typ.clone(), right_typ_attr.clone())];
        let (left_module_str, left_package_str) = left.import_item_clone().fields_move();
        let (exists, func_str) = 
            match self.function_is_exist(consts::OPERATOR_IS_FUNCTION_NAME
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
        /*
        self.call_function(func_statement, func_define, PackageStr::Empty
            , desc_ctx, param_len)
        */
        DescResult::Success
    }

    fn is_interface_process(&mut self, define: Interface) -> DescResult {
        let right = match self.scope_context.take_top_from_value_buffer() {
            Ok(o) => o,
            Err(err) => {
                return err;
            }
        };
        let left = self.scope_context.take_top_from_value_buffer();
        let (right_typ, right_addr, right_typ_attr, right_import_item, right_context) = right.fields_move();
        let (right_module_str, right_package_str) = right_import_item.fields_move();
        let interface_define = define.interface_obj_ref().pop();
        match right_package_str {
            PackageStr::Itself => {
                match interface_define.function_statemet_ref() {
                    Some(s) => s,
                    None => {
                        /*
                         * interface 中没有函数 => 一定满足
                         * */
                        unimplemented!();
                    }
                }
                self.interface_control.iter_define(&right_module_str, interface_define.name_ref()
                            , |name: &String, de: &InterfaceDefine| -> bool {
                                /*
                                 * TODO: 不应该迭代 InterfaceControl, 应该 先找到 InterfaceDefine,
                                 * 再迭代 InterfaceDefine
                                 * */
                                let expect_func_str = FunctionSplice::get_function_without_return_string_by_type(
                                    &func_name, &Some(&param), &Some(&input_typ));
                                // println!("{:?}", expect_func_str);
                                /*
                                 * 查找方法
                                 * */
                                let (input_module_str, input_package_str) = input_import_item.fields_move();
                                let find_func_context = FindFunctionContext {
                                    func_name: &func_name,
                                    typ: Some(&input_typ),
                                    package_str: input_package_str.clone(),
                                    func_str: &expect_func_str,
                                    module_str: self.module_stack.current().name_ref()
                                };
                                let (exists, handle) = self.function_control.is_exists(&find_func_context);
                                false
                            });
            },
            _ => {
                unimplemented!();
            }
        }
        define.interface_obj_ref().push(interface_define);
        // self.interface_control.iter_define();
        /*
         * 判断 left 中是否含有 right 的所有方法
         * */
        DescResult::Success
    }
}


use libresult::DescResult;
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{FunctionDefineParamContext
    , FunctionDefineParamContextType
    , FunctionDefineParamMutContext
    , FunctionDefineReturnContext
    , FunctionDefineContext
    , InterfaceFunctionStatementContext
    , TypeToken};
use libtype::function::{AddFunctionContext
    , FunctionParamDataItem, FunctionParam
    , FunctionParamData
    , FunctionReturnData, FunctionReturn
    , FunctionStatement};
use libtype::{TypeAttrubute, Type
    , AddressKey, AddressValue
    , AddressType};
use libtype::interface::{InterfaceDefine
    , InterfaceFunctionStatement};
use libtype::instruction::{JumpType, Jump};
use libtype::package::{PackageStr};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext
    , TypeTokenExpand};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::ScopeType;
use crate::define::{DefineObject};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_interface_define_start(&mut self
        , define: &mut InterfaceDefine) -> DescResult {
        DescResult::Success
    }

    pub fn process_interface_define_end(&mut self
        , define: &mut InterfaceDefine) -> DescResult {
        DescResult::Success
    }

    pub fn process_interface_function_define_param(&mut self
        , define: &mut InterfaceDefine, context: FunctionDefineParamContext)
        -> DescResult {
        let func_statement = match define.function_statement_mut() {
            Some(statements) => {
                if statements.is_empty() {
                    panic!("function statement is empty");
                }
                statements.last_mut().unwrap()
            },
            None => {
                panic!("function statement is none");
            }
        };
        let (name_token, t, typ_attr, lengthen_attr, param_no)
            = context.fields_move();
        let typ = match t {
            FunctionDefineParamContextType::Token(token) => {
                match self.to_type(token) {
                    Ok(ty) => ty,
                    Err(err) => {
                        return err;
                    }
                }
            },
            FunctionDefineParamContextType::Typ(ty) => {
                ty
            }
        };
        let item = FunctionParamDataItem{
            typ: typ,
            typ_attr: typ_attr,
            lengthen_attr: lengthen_attr,
            is_auto_call_totype: false,
            is_check_func_call_param_typ_attr: true
        };
        match func_statement.func_param_mut() {
            Some(param) => {
                match &mut param.data {
                    FunctionParamData::Single(p) => {
                        /*
                         * 将 single 转换为 multi
                         * */
                        let params = vec![p.clone(), item];
                        *&mut param.data = FunctionParamData::Multi(params);
                    },
                    FunctionParamData::Multi(ps) => {
                        ps.push(item);
                    }
                }
            },
            None => {
                /*
                 * 没有参数 => 设置为一个参数
                 * */
                *func_statement.func_param_mut() = Some(FunctionParam{
                    data: FunctionParamData::Single(item)
                });
            }
        }
        DescResult::Success
    }

    pub fn process_interface_function_statement_start(&mut self, define: &mut InterfaceDefine
        , context: &mut InterfaceFunctionStatementContext)
        -> DescResult {
        /*
         * 添加一个 statement
         * */
        match define.function_statement_mut() {
            Some(def) => {
                def.push(InterfaceFunctionStatement::default());
            },
            None => {
                *define.function_statement_mut() = Some(vec![InterfaceFunctionStatement::default()]);
            }
        }
        DescResult::Success
    }

    pub fn process_interface_function_statement_end(&mut self, define: &mut InterfaceDefine
        , context: &mut InterfaceFunctionStatementContext)
        -> DescResult {
        DescResult::Success
    }

    pub fn process_interface_start(&mut self, define: &mut InterfaceDefine) -> DescResult {
        DescResult::Success
    }

    pub fn process_interface_end(&mut self, define: InterfaceDefine) -> DescResult {
        self.interface_control.add_define(
            self.module_stack.current().name_clone()
            , define.name_ref().clone()
            , define);
        DescResult::Success
    }
}


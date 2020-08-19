use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{FunctionDefineParamContext
    , FunctionDefineReturnContext};
use libtype::function::{AddFunctionContext
    , FunctionParamDataItem
    , FunctionReturnData, FunctionReturn
    , FunctionStatement};
use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, Type
    , AddressKey, AddressValue
    , AddressType};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext
    , TypeTokenExpand};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::ScopeType;
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_function_named_stmt(&mut self, value: TokenValue) {
        self.scope_context.enter(ScopeType::Function);
        let s = match value.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        let statement_ptr = self.cb.function_named_stmt(FunctionNamedStmtContext{
            name: s
        });
    }

    pub fn handle_function_define_param(&mut self, context: FunctionDefineParamContext) {
        let (name_token, type_token, typ_attr, lengthen_attr, param_no)
            = context.fields_move();
        let name = extract_token_data!(
           name_token.token_data().expect("should not happend")
           , Id);
        let typ = extract_token_data!(
            type_token.token_data().expect("should not happend")
            , Id);
        let typ = Type::from_str(&typ);
        /*
         * 为参数分配一个地址
         *  只是分配一个地址, 不做其他事情 (就是增加地址分配器的索引,
         *  函数体中的起始地址是从参数个数开始的)
         * */
        self.scope_context.alloc_address(
            typ.to_address_type(), 0);
        /*
         * 添加到变量列表中
         * 其中:
         *  地址是参数的序号
         * */
        self.scope_context.add_variant(name
            , Variant::new_with_all(
                Address::new(AddressValue::new(typ.to_address_type()
                        , AddressKey::new(param_no as u64)))
                , typ.clone(), typ_attr.clone()));
        /*
         * 填充函数声明
         * */
        let func_param_item = FunctionParamDataItem::new_with_all(
            typ, typ_attr, lengthen_attr, false);
        self.cb.function_push_param_to_statement(func_param_item);
    }

    pub fn handle_function_define_return(&mut self, context: FunctionDefineReturnContext) {
        let (typ_attr, _, type_token) = context.fields_move();
        let func_return_data = FunctionReturnData::new(
            type_token.to_type(), typ_attr);
        let func_return = FunctionReturn::new(func_return_data);
        self.scope_context.set_current_func_return(func_return.clone());
        self.cb.function_set_return_to_statement(func_return);
    }

    pub fn handle_function_define_start(&mut self) {
        self.cb.function_define_start();
    }

    pub fn handle_function_define_end(&mut self) {
        // println!("{:?}", self.scope_context.get_current_func_return_ref());
        let func = self.cb.function_define_end();
        // println!("{:?}", func.func_statement_ref().statement_full_str());
        let package_typ = PackageType::new(PackageTypeValue::Crate);
        let context = AddFunctionContext{
            typ: None,
            package_typ: Some(&package_typ),
            module_str: self.module_stack.current().to_str().to_string(),
            // func_str: func.func_statement_ref().func_name.clone()
            func_str: func.func_statement_ref().statement_full_str().to_string()
        };
        // println!("{:?}", func);
        self.function_control.add_function(context, None, func);
        self.scope_context.leave();
    }
}

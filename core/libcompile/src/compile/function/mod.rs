use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{FunctionDefineParamContext};
use libtype::function::{AddFunctionContext};
use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute, Type
    , AddressKey, AddressValue
    , AddressType};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};
use crate::compile::scope::vars::Variant;
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_function_named_stmt(&mut self, value: TokenValue) {
        self.scope_context.enter();
        let s = match value.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        self.cb.function_named_stmt(FunctionNamedStmtContext{
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
         * 1. 生成参数加载指令
         * 2. 填充函数声明
         * */
        /*
         * 添加到变量列表中
         * 其中:
         *  地址是参数的序号
         * */
        self.scope_context.add_variant(name
            , Variant::new_with_all(
                Address::new(AddressValue::new(typ.to_address_type()
                        , AddressKey::new(param_no as u64)))
                , typ, typ_attr));
    }

    pub fn handle_function_define_start(&mut self) {
        self.cb.function_define_start();
    }

    pub fn handle_function_define_end(&mut self) {
        let func = self.cb.function_define_end();
        let package_typ = PackageType::new(PackageTypeValue::Crate);
        let context = AddFunctionContext{
            typ: None,
            package_typ: Some(&package_typ),
            module_str: self.module_stack.current().to_str().to_string(),
            func_str: func.func_statement_ref().func_name.clone()
        };
        self.function_control.add_function(context, None, func);
        self.scope_context.leave();
    }
}

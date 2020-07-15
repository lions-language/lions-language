use crate::Type;
use crate::function::{FunctionParamData, FunctionReturnData};

pub struct FunctionSplice;

impl FunctionSplice {
    pub fn get_function_without_return_string_by_type(
        func_name: &str, func_param: &Option<&FunctionParamData>
        , typ: &Option<&Type>) -> String {
        FunctionSplice::get_function_string_by_type(
            func_name, func_param, &None, typ)
    }

    pub fn get_function_without_return_and_type_string(
        func_name: &str, func_param: &Option<&FunctionParamData>) -> String {
        FunctionSplice::get_function_string_by_type(
            func_name, func_param, &None, &None)
    }

    pub fn get_function_string_by_type(func_name: &str, func_param: &Option<&FunctionParamData>
            , func_return: &Option<&FunctionReturnData>, typ: &Option<&Type>) -> String {
        /*
         * 函数名(参数类型列表)->(返回值类型列表)
         * */
        let mut s = String::new();
        /*
         * 存在类型名
         * */
        match typ {
            Some(t) => {
                s.push_str(t.to_attrubute_str());
                s.push_str(t.to_str());
                s.push(':');
            },
            None => {
            }
        }
        /*
         * 拼接函数名
         * */
        s.push_str(&func_name);
        /*
         * 拼接参数列表
         * */
        s.push('(');
        match func_param {
            Some(param) => {
                match param {
                    FunctionParamData::Single(p) => {
                        s.push_str(p.typ.to_attrubute_str());
                        s.push_str(p.typ.to_str());
                    },
                    FunctionParamData::Multi(ps) => {
                        for (i, p) in ps.iter().enumerate() {
                            if i > 0 {
                                s.push(',');
                            }
                            s.push_str(p.typ.to_attrubute_str());
                            s.push_str(p.typ.to_str());
                        }
                    }
                }
            },
            None => {
            }
        }
        s.push(')');
        /*
         * 拼接返回值
         * */
        match func_return {
            Some(ret) => {
                s.push_str("->");
                s.push_str(ret.typ.to_attrubute_str());
                s.push_str(ret.typ.to_str());
            },
            None => {
            }
        }
        s
    }
}

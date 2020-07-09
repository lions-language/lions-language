use super::{FunctionStatement, FunctionParam, FunctionReturn
        , FunctionParamData};
use crate::{Type};

impl FunctionStatement {
    fn calc_function_statement_string_append_type(&self, s: &mut String
            , typ: &Option<&Type>) {
        match typ {
            Some(t) => {
                s.push_str(t.to_str());
            },
            None => {
            }
        }
    }

    fn calc_function_statement_string(func_name: &str, func_param: &Option<FunctionParam>
            , func_return: &Option<FunctionReturn>, typ: &Option<Type>) -> String {
        /*
         * 函数名(参数类型列表)->(返回值类型列表)
         * */
        let mut s = String::new();
        /*
         * 存在类型名
         * */
        match typ {
            Some(t) => {
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
        match func_param {
            Some(param) => {
                match &param.data {
                    FunctionParamData::Single(p) => {
                        s.push('(');
                        s.push_str(p.typ.to_str());
                        s.push(')');
                    },
                    FunctionParamData::Multi(ps) => {
                        s.push('(');
                        for (i, p) in ps.iter().enumerate() {
                            if i > 0 {
                                s.push(',');
                            }
                            s.push_str(p.typ.to_str());
                        }
                        s.push(')');
                    }
                }
            },
            None => {
            }
        }
        /*
         * 拼接返回值
         * */
        s
    }
}

impl FunctionStatement {
    pub fn new(func_name: String, func_param: Option<FunctionParam>
            , func_return: Option<FunctionReturn>, typ: Option<Type>) -> Self {
        Self {
            func_name: func_name,
            func_param: func_param,
            func_return: func_return,
            typ: typ
        }
    }
}

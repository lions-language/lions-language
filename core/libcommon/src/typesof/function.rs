pub struct FunctionObject {
    function_str: String,
    type_function_str: String
}

impl FunctionObject {
    /*
     * 函数 new 的时候应该 to string(存储到成员), 而不是在获取时再拼接, 加快访问效率
     * */
    pub fn function_string(&self) -> &str {
        /*
         * 函数名_参数类型_返回值类型
         * */
        return &self.function_str
    }

    pub fn type_function_string(&self) -> &str {
        return &self.type_function_str
    }
}

/*
pub struct FunctionDefineDispatch {
    /*
     * 函数名 <-> 定义对象
     * */
    funcs: HashMap<String, FunctionDefine>
}

impl FunctionDefineDispatch {
    pub fn alloc_define(&mut self, func_name: String) -> DefineObject {
        let def = FunctionDefine::new();
        /*
         * 关键点: 获取插入后的元素的引用
         * */
        let v = self.funcs.entry(func_name).insert(def);
        let v = v.get();
        DefineObject::from_ref_typ::<FunctionDefine>(v, DefineType::Function.into())
    }

    pub fn new() -> Self {
        Self {
            funcs: HashMap::new()
        }
    }
}
*/
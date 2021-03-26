## libfunctiontype
### FunctionContrl
#### 作用
- 存储一个 包 中的所有函数
    - 所以, 这里面增/删 都不存在 package_str 属性
- 对于第三方包, 应该在解析完成之后, 构造出 FunctionControl 对象, 然后添加到 Package(libcompile:packag/mod.rs) 中, 当其他包引入这个包的时候, 直接从 PackageControl(libcompile:package/mod.rs) 中获取


## 

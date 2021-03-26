## import 语句
### 概述
- 对于本地模块而言, 直接读取内存中解析后的数据
- 对于系统包/外部包, 需要通过外部的指针对象进行访问
    - 一开始会获取依赖的包, 并下载到本地, 需要访问的时候, 将下载的二进制文件读取到内存中, 以后使用这些包的时候, 就会从这些指针对象中获取

### 对于module
- 通过 import 的路径, 计算出距离 根的 path, 将这个完整的 path, 写入到 module 中


## 记录import结果
### 文件
- compile/import_mapping.rs

### import结果 结构
- 保存了 PackageStr 和 ModuleStr 信息


## 双冒号(::)访问
- 最多只会有一次 :: 访问, 因为 import语句已经将导入的包解析完毕了


## 点(.)操作
- 因为是表达式操作, 所以需要在 nup / led 中执行
    - 并且是在 两个 id 之间的, 那么必然在 grammar/id/mod.rs 中处理
- 通过 enter_point_access 和 leave_point_access 告知compile 层, 让 compile层 在 enter/leave 记录需要的上下文信息


## 什么时候确定 PackageStr
- 定义的时候一定是 Itself, 所以在定义的时候, 没有必要设置
- 只有在 load 的时候才能辨别是 Itself, 还是 other
    - 如果有前缀(::操作符), 说明是 other, 此时直接从 imports 中获取 package_str 和 module_str
    
### 变量结构中存储的信息
- Variant中存储 Package, 便于对变量的跟踪


## 函数调用
### 参数类型
- 首先判断 Type 是什么, 再判断怎么处理相应的类型
    - 比如: 判断 typ是 Structure, 那么就处理 结构体; 如果typ是 Interface, 就处理接口


## operator/is_opt 处理
- 判断right的类型是否是 interface, 如果是interface, 需要进行特殊处理


## module_stack
### 说明
- 每次进入一个模块的时候, 都会将其推入到 module_stack 中


## 第三方包
### 


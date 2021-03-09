## import 语句
- 对于本地模块而言, 直接读取内存中解析后的数据
- 对于系统包/外部包, 需要通过外部的指针对象进行访问
    - 一开始会获取依赖的包, 并下载到本地, 需要访问的时候, 将下载的二进制文件读取到内存中, 以后使用这些包的时候, 就会从这些指针对象中获取


## 记录import结果
### 文件
- compile/import_mapping.rs


## 双冒号(::)访问
- 最多只会有一次 :: 访问, 因为 import语句已经将导入的包解析完毕了


## 点(.)操作
- 因为是表达式操作, 所以需要在 nup / led 中执行
    - 并且是在 两个 id 之间的, 那么必然在 grammar/id/mod.rs 中处理
- 通过 enter_point_access 和 leave_point_access 告知compile 层, 让 compile层 在 enter/leave 记录需要的上下文信息


## impl语句


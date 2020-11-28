use libcompile::static_stream::{StaticStream};
use libcommon::ptr::RefPtr;
use libtype::instruction::Instruction;
use libtype::package::PackageStr;
use libtype::{Data, AddressKey};
use std::collections::VecDeque;

pub struct LinkStatic {
    static_stream: RefPtr,
    static_area: VecDeque<Data>,
    other_addr: usize
}

impl LinkStatic {
    pub fn process(&mut self, instruction: &Instruction
        , package_str: Option<&PackageStr>) {
        match instruction {
            Instruction::ReadStaticVariant(value) => {
                // let ps = value.package_str_ref();
                let ps = match package_str {
                    Some(ps) => ps.clone(),
                    None => {
                        value.package_str_clone()
                    }
                };
                match ps {
                    PackageStr::Itself => {
                        /*
                         * 由于是自身包中的静态量 => 不用重新定义地址
                         * */
                    },
                    _ => {
                        /*
                         * 1. 查看是否加载过该包
                         *  未加载过: 读取包中的静态区域, 然后追加到这里, 并写入内存
                         * 2. 更改地址
                         * */
                        unimplemented!();
                    }
                }
            },
            _ => {
            }
        }
    }

    pub fn start(&mut self) {
        /*
         * 编译结束后进入这里
         *  1. 将编译得到的静态区域拷贝过来
         * */
        let length = self.static_stream.as_ref::<StaticStream>().length();
        self.other_addr = length;
        let mut static_area = VecDeque::with_capacity(length);
        static_area.append(self.static_stream.as_mut::<StaticStream>().datas_mut());
        *&mut self.static_area = static_area;
    }

    pub fn new(static_stream: RefPtr) -> Self {
        /*
         * 将本包的静态区拷贝到总的静态区
         * */
        Self {
            static_stream: static_stream,
            static_area: VecDeque::new(),
            other_addr: 0
        }
    }

    pub fn read_uncheck(&self, addr: &AddressKey) -> &Data {
        let index = addr.index_clone() as usize;
        self.static_area.get(index).expect(&format!("addr is not exist, index: {}", index))
    }
}

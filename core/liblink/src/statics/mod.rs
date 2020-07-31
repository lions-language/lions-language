use libcompile::static_stream::{StaticStream};
use libcommon::ptr::RefPtr;
use libtype::instruction::Instruction;
use libtype::package::PackageStr;
use libtype::Data;
use std::collections::VecDeque;

pub struct LinkStatic {
    static_stream: RefPtr,
    static_area: VecDeque<Data>,
    other_addr: usize
}

impl LinkStatic {
    pub fn process(&mut self, instruction: &Instruction) {
        match instruction {
            Instruction::ReadStaticVariant(value) => {
                let ps = value.package_str_ref();
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

    pub fn new(mut static_stream: RefPtr) -> Self {
        let length = static_stream.as_ref::<StaticStream>().length();
        /*
         * 将本包的静态区拷贝到总的静态区
         * */
        let mut static_area = VecDeque::with_capacity(length);
        static_area.append(static_stream.as_mut::<StaticStream>().datas_mut());
        Self {
            static_stream: static_stream,
            static_area: VecDeque::with_capacity(length),
            other_addr: length
        }
    }

    pub fn read_uncheck(&self, addr: usize) -> &Data {
        self.static_area.get(addr).expect("addr is not exist")
    }
}

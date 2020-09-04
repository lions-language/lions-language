use super::{StructDefine};

impl StructDefine {
    pub fn print(&self) {
        println!("name: {:?}", self.name);
        match self.member_ref() {
            Some(m) => {
                println!("member: ");
                m.print_members();
            },
            None => {
            }
        }
    }
}


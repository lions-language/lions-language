use super::{StructDefine};

impl StructDefine {
    pub fn member_length(&self) -> usize {
        match self.member_ref() {
            Some(m) => {
                m.length()
            },
            None => {
                0
            }
        }
    }

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


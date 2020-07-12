pub struct Module {
    name: String
}

impl Module {
    pub fn new(name: String) -> Self {
        Self {
            name: name
        }
    }
}

mod module;


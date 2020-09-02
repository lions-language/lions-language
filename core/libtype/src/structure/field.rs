use super::{StructField};

impl StructField {
    pub fn clone_with_index_plus(&self, index: usize) -> Self {
        let mut f = self.clone();
        *f.index_mut() += index;
        f
    }
}


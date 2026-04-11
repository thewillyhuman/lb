pub mod lookup_table;
pub mod permutation;

pub use lookup_table::LookupTable;

/// Default Maglev lookup table size (must be prime, M >> N).
pub const DEFAULT_TABLE_SIZE: usize = 65537;

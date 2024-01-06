use wasmer::{Engine, Module};

#[derive(Debug, Clone)]
pub struct CachedModule {
    pub module: Module,
    /// The runtime engine to run this module. Ideally we could use a single engine
    /// for all modules but the memory issue described in <https://github.com/wasmerio/wasmer/issues/4377>
    /// requires using one engine per module as a workaround.
    pub engine: Engine,
    /// The estimated size of this element in memory.
    /// Since the cached modules are just [rkyv](https://rkyv.org/) dumps of the Module
    /// instances, we use the file size of the module on disk (not the Wasm!)
    /// as an estimate for this.
    /// Note: Since CosmWasm 1.4 (Wasmer 4), Store/Engine are not cached anymore.
    /// The majority of the Module size is the Artifact.
    pub size_estimate: usize,
}

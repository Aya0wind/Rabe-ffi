# Rabe-ffi
Rust Attribute-Based Encryption library [rabe](https://github.com/Fraunhofer-AISEC/rabe)'s C FFI binding , support CP-ABE and KP-ABE encrypt and decrypt, submodule of Rabe.Core c# library.
## Build
1. Install rust  
   + ```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```
2. Set default toolchain to nightly  
   + ```rustup default nightly```
3. Clone and build project  
   + ```git clone https://github.com/Aya0wind/Rabe-ffi.git```  
   + ```cd Rabe-ffi```  
   + ```cargo build --release```
4. Add dynamic link library to your c project
   + ```cp target/release/librabe_ffi.so /your/project/path```
5. Add bindings.h to your c project as a c header file  
   + ```cp rabe.h /your/project/path/yourheadername.h```
## Documentation
See unit tests in sources.

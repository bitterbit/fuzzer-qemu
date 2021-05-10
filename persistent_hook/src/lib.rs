use std::os::raw::c_int;

#[no_mangle]
pub extern fn afl_persistent_hook_init() -> c_int {
    println!("afl_persistent_hook init");
    return 1;
}

#[no_mangle]
pub extern fn afl_persistent_hook() {
    println!("afl_persistent_hook!");
}

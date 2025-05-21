pub mod api;
mod frb_generated;
mod utils;

#[no_mangle]
pub extern "C" fn frb_create_shutdown_callback() {}

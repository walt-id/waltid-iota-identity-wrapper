#[macro_use]
extern crate lazy_static;

use std::{ffi::CString, os::raw::c_char};
use identity_iota::{account::{Account, IdentitySetup}, iota_core::IotaDID};
use tokio::runtime::Runtime;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[no_mangle]
pub extern fn create_did() -> *mut c_char {
    let account: Account =  RUNTIME.block_on(
        async move { 
            Account::builder().create_identity(IdentitySetup::default()).await
        }
    ).unwrap();
    
    let iota_did: &IotaDID = account.did();
    println!("[Example] Local Document from {} = {:#?}", iota_did, account.document());
    let did_doc = format!("{:#?}", account.document().core_document());
    return CString::new(did_doc).unwrap().into_raw()
}

#[no_mangle]
pub extern fn free_str(str: *mut i8) {
    // retake pointer to free memory
    let _ = unsafe { CString::from_raw(str) };
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::create_did;

    #[test]
    fn it_works() {
        let didDocRaw = create_did();
        let did_doc = unsafe {
            CStr::from_ptr(didDocRaw)
        }.to_str().unwrap();
        println!("{did_doc}")
    }
}

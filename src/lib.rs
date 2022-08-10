#[macro_use]
extern crate lazy_static;

use std::{ffi::{CString, CStr}, os::raw::c_char, slice, ptr::{null_mut}};
use identity_iota::{account::{Account, IdentitySetup}, iota_core::IotaDID, prelude::{KeyPair, KeyType}, core::ToJson, client::{Resolver}};
use tokio::runtime::Runtime;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[no_mangle]
pub extern fn create_did(priv_key: *const u8, key_len: usize) -> *mut c_char {
    let mut identity_setup = IdentitySetup::default();
    if !priv_key.is_null() && key_len > 0 {
        let kp = unsafe { KeyPair::try_from_private_key_bytes(
            KeyType::Ed25519, 
            slice::from_raw_parts(priv_key, key_len)) 
        }.unwrap();
        let pk: Box<[u8]> = kp.private().as_ref().into();
        identity_setup = identity_setup.private_key(pk.into())
    }
    let account: Result<Account, _> =  RUNTIME.block_on(
        async move { 
            Account::builder().create_identity(identity_setup).await
        }
    );
    
    if account.is_ok() {
        let did_doc = account.unwrap().document().core_document().to_jcs().unwrap();
        return CString::new(did_doc).unwrap().into_raw()
    } else {
        return null_mut()
    }
}

#[no_mangle]
pub extern fn resolve_did(did: *const c_char) -> *mut c_char {
    let did_str = unsafe { CStr::from_ptr(did).to_str() }.unwrap();
    let doc = RUNTIME.block_on(
        async move {
            let resolver: Resolver = Resolver::new().await?;
            let did: IotaDID = IotaDID::parse(did_str)?;
            resolver.resolve(&did).await
        }
    );
    if doc.is_ok() {
        return CString::new(doc.unwrap().document.core_document().to_jcs().unwrap()).unwrap().into_raw();
    } else {
        return null_mut();
    }
}

#[no_mangle]
pub extern fn free_str(str: *mut i8) {
    // retake pointer to free memory
    let _ = unsafe { CString::from_raw(str) };
}

#[cfg(test)]
mod tests {
    use std::{ffi::{CStr, CString}, ptr::null};

    use crate::{create_did, resolve_did, free_str};

    #[test]
    fn test_create_did() {
        let didDocRaw = create_did(null(), 0);
        let did_doc = unsafe {
            CStr::from_ptr(didDocRaw)
        }.to_str().unwrap();
        println!("{did_doc}");
        free_str(didDocRaw);
    }

    #[test]
    fn test_resolve_did() {
        let didRaw = CString::new("did:iota:13FUaeSdUBQ3gCYba59yhUHBZZCVkJfiDHBhigztNVLc").unwrap().into_raw();
        let didDocRaw = resolve_did(didRaw);
        assert!(!didDocRaw.is_null());
        if !didDocRaw.is_null() {
            let did_doc = unsafe {
                CStr::from_ptr(didDocRaw)
            }.to_str().unwrap();
            println!("{did_doc}");
            free_str(didDocRaw);
        }
        free_str(didRaw)
    }
}

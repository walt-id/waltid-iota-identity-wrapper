#[macro_use]
extern crate lazy_static;

use std::{ffi::{CString, CStr}, os::raw::c_char, slice, ptr::{null_mut}, fmt::format};
use identity_iota::{account::{Account, IdentitySetup, MethodContent}, iota_core::IotaDID, prelude::{KeyPair, KeyType}, core::ToJson, client::{Resolver}, did::MethodRelationship, crypto::{Ed25519, PublicKey}};
use tokio::runtime::Runtime;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[no_mangle]
pub extern fn create_did(priv_key: *const u8, key_len: usize) -> *mut c_char {
    let account: Result<Account, _> =  RUNTIME.block_on(
        async move { 
            create_did_async(priv_key, key_len).await
        }
    );
    
    if account.is_ok() {
        let did_doc = account.unwrap().document().core_document().to_json_pretty().unwrap();
        return CString::new(did_doc).unwrap().into_raw()
    } else {
        println!("{}", account.unwrap_err().to_string());
        return null_mut()
    }
}

async fn create_did_async(priv_key: *const u8, key_len: usize) -> Result<Account, identity_iota::account::Error> {
    let mut identity_setup = IdentitySetup::default();
    if !priv_key.is_null() && key_len > 0 {
        let kp = unsafe { KeyPair::try_from_private_key_bytes(
            KeyType::Ed25519, 
            slice::from_raw_parts(priv_key, key_len)) 
        }.unwrap();
        let pk: Box<[u8]> = kp.private().as_ref().into();
        identity_setup = identity_setup.private_key(pk.into());
    }
    println!("Creating new account...");
    let mut account = Account::builder().create_identity(identity_setup).await?;
    println!("Created account: {}", account.did().to_string());

    let signing_method = account.document().default_signing_method().unwrap();
    println!("Default signing method: {}", signing_method.to_json_pretty().unwrap());
    let fragment0 = signing_method.id().fragment().unwrap().to_string();
    let fragment1 = format!("{}.1", fragment0);
    let pub_key = PublicKey::from(signing_method.data().try_decode().unwrap());
    println!("Creating generic verification method...");
    account.update_identity().create_method().content(MethodContent::PublicEd25519(pub_key)).fragment(&fragment1).apply().await?;
    println!("Updating verification relationships...");
    account.update_identity()
    .attach_method_relationship().fragment(&fragment1).relationships(
        [
            MethodRelationship::AssertionMethod,
            MethodRelationship::Authentication,
            MethodRelationship::CapabilityDelegation,
            MethodRelationship::CapabilityInvocation,
            MethodRelationship::KeyAgreement
        ]
    ).apply().await?;
    println!("Removing default signing method...");
    account.update_identity().delete_method().fragment(&fragment0).apply().await?;
    Ok(account)
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
        return CString::new(doc.unwrap().document.core_document().to_json().unwrap()).unwrap().into_raw();
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
    use std::{ffi::{CStr, CString}, ptr::{null, null_mut}, slice};

    use identity_iota::prelude::{KeyPair, KeyType};

    use crate::{create_did, resolve_did, free_str};

    #[test]
    fn test_create_did() {
        let kp = KeyPair::new(KeyType::Ed25519).unwrap();
        let prv_bytes: &[u8] = kp.private().as_ref();
        let did_doc_raw = create_did(prv_bytes.as_ptr(), prv_bytes.len());
        let did_doc = unsafe {
            CStr::from_ptr(did_doc_raw)
        }.to_str().unwrap();
        println!("{did_doc}");
        free_str(did_doc_raw);
    }

    #[test]
    fn test_create_did_generating_key() {
        let did_doc_raw = create_did(null_mut(), 0);
        let did_doc = unsafe {
            CStr::from_ptr(did_doc_raw)
        }.to_str().unwrap();
        println!("{did_doc}");
        free_str(did_doc_raw);
    }

    #[test]
    fn test_resolve_did() {
        let did_raw = CString::new("did:iota:13FUaeSdUBQ3gCYba59yhUHBZZCVkJfiDHBhigztNVLc").unwrap().into_raw();
        let did_doc_raw = resolve_did(did_raw);
        assert!(!did_doc_raw.is_null());
        if !did_doc_raw.is_null() {
            let did_doc = unsafe {
                CStr::from_ptr(did_doc_raw)
            }.to_str().unwrap();
            println!("{did_doc}");
            free_str(did_doc_raw);
        }
        free_str(did_raw)
    }
}

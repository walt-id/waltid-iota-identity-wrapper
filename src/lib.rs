#[macro_use]
extern crate lazy_static;
mod dids;
mod store;

use std::{ffi::{CString, CStr}, os::raw::c_char, slice, ptr::{null_mut}, fmt::{format, Debug}};
use std::ptr::null;
use identity_core::convert::ToJson;
use identity_core::crypto::{KeyPair, KeyType};
use tokio::runtime::Runtime;
use uuid::Uuid;
use crate::dids::{create_account_async, resolve_did_async};

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[no_mangle]
pub extern fn create_did(priv_key: *const u8, key_len: usize) -> *mut c_char {
    let document =  RUNTIME.block_on(
        async move {
            create_account_async(priv_key, key_len).await
        }
    );

    if document.is_ok() {
        let did_doc = document.unwrap().core_document().to_json_pretty().unwrap();
        return CString::new(did_doc).unwrap().into_raw()
    } else {
        println!("{}", document.unwrap_err().to_string());
        return null_mut()
    }
}

#[no_mangle]
pub extern fn create_did_offline(priv_key: *const u8, key_len: usize) -> *mut c_char {
    let kp = unsafe { KeyPair::try_from_private_key_bytes(
        KeyType::Ed25519,
        slice::from_raw_parts(priv_key, key_len))
    }.unwrap();
    let document= dids::create_did(&kp);
    if document.is_ok() {
        let did_doc = document.unwrap().core_document().to_json_pretty().unwrap();
        return CString::new(did_doc).unwrap().into_raw()
    } else {
        println!("{}", document.unwrap_err().to_string());
        return null_mut()
    }
}

#[no_mangle]
pub extern fn resolve_did(did: *const c_char) -> *mut c_char {
    let did_str = unsafe { CStr::from_ptr(did).to_str() }.unwrap();
    let doc = RUNTIME.block_on(
        async move {
            resolve_did_async(String::from(did_str)).await
        }
    );
    if doc.is_ok() {
        return CString::new(doc.unwrap().core_document().to_json().unwrap()).unwrap().into_raw();
    } else {
        println!("{}", doc.unwrap_err().to_string());
        return null_mut();
    }
}



async fn validate_credential_async(credential_json: String) -> Result<bool, identity_iota::account::Error> {
    let credential: Credential = Credential::from_json(credential_json.as_str())?;
    println!("Credential: {}", credential.to_json_pretty()?);

    let issuer_did = credential.issuer.url().to_string();
    println!("Issuer DID: {}", issuer_did);
    let issuer_doc = resolve_did_async(issuer_did).await?;
    println!("{}", issuer_doc.to_json_pretty().unwrap());

    let result = CredentialValidator::validate(&credential, &issuer_doc, &CredentialValidationOptions::default(), FailFast::FirstError);
    if result.is_ok() {
        println!("Validation successful!");
        Ok(true)
    } else {
        let err_msg = result.unwrap_err().to_string();
        println!("Validation failed: {}", &err_msg);
        Err(identity_iota::credential::Error::InvalidStatus(err_msg).into())
    }
}

pub fn validate_credential(credential_json: String) -> bool {
    let valid = RUNTIME.block_on(async move {
        validate_credential_async(credential_json).await
    });
    if valid.is_ok() {
        valid.unwrap()
    } else {
        false
    }
}

// async fn issue_credential_async() -> Result<String, identity_iota::account::Error> {
//     let issuer = create_did_async(null(), 0).await?;
//
//     let subject: Subject = Subject::from_json_value(json!({
//         "id": issuer.id(),
//         "currentAddress" : [ "1 Boulevard de la Liberté, 59800 Lille" ],
//         "dateOfBirth" : "1993-04-08",
//         "familyName" : "DOE",
//         "firstName" : "Jane",
//         "gender" : "FEMALE",
//         "nameAndFamilyNameAtBirth" : "Jane DOE",
//         "personalIdentifier" : "0904008084H",
//         "placeOfBirth" : "LILLE, FRANCE",
//       }))?;
//
//     let mut credential: Credential = CredentialBuilder::default()
//         .id(Url::parse("https://example.edu/credentials/3732")?)
//         .issuer(Url::parse(issuer.id().as_str())?)
//         .type_("VerifiableId")
//         .subject(subject)
//         .build()?;
//
//     issuer
//         .sign(issuer.default_signing_method()?.id().fragment().unwrap(), &mut credential, ProofOptions::default())
//         .await?;
//
//     println!("Credential JSON > {:#}", credential);
//
//     Ok(credential.to_json().unwrap())
// }

// pub fn issue_credential() -> Result<String, identity_iota::account::Error> {
//     RUNTIME.block_on(async move {
//         issue_credential_async().await
//     })
// }

#[no_mangle]
pub extern fn free_str(str: *mut i8) {
    // retake pointer to free memory
    let _ = unsafe { CString::from_raw(str) };
}

#[cfg(test)]
mod tests {
    use std::{ffi::{CStr, CString}, ptr::{null, null_mut}, slice};
    use identity_core::crypto::{KeyPair, KeyType};

    use crate::{create_did, resolve_did, free_str, validate_credential, create_did_offline, IotaDocument};

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
    fn test_create_did_offline() {
        let kp = KeyPair::new(KeyType::Ed25519).unwrap();
        let prv_bytes: &[u8] = kp.private().as_ref();
        let did_doc_raw = create_did_offline(prv_bytes.as_ptr(), prv_bytes.len());
        let did_doc = unsafe {
            CStr::from_ptr(did_doc_raw)
        }.to_str().unwrap();
        println!("{did_doc}");
        free_str(did_doc_raw);
    }

    #[test]
    fn test_create_did_2_ways() {
        let kp = KeyPair::new(KeyType::Ed25519).unwrap();
        let prv_bytes: &[u8] = kp.private().as_ref();
        let did_doc_raw_1 = create_did_offline(prv_bytes.as_ptr(), prv_bytes.len());
        let did_doc_raw_2 = create_did(prv_bytes.as_ptr(), prv_bytes.len());
        let did_doc_1 = unsafe {
            CStr::from_ptr(did_doc_raw_1)
        }.to_str().unwrap();
        let did_doc_2 = unsafe {
            CStr::from_ptr(did_doc_raw_2)
        }.to_str().unwrap();

        println!("{did_doc_1}");
        println!("{did_doc_2}");
        free_str(did_doc_raw_1);
        free_str(did_doc_raw_2);
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
        let did_raw = CString::new("did:iota:5MB5Tmsim8eriMB8wim6K6tARdNuLZuUVjg9f9jUy6QF").unwrap().into_raw();
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

    #[test]
    fn test_validate_credential() {
        let vc = r#"{
  "@context" : [ "https://www.w3.org/2018/credentials/v1" ],
  "credentialSchema" : {
    "id" : "https://api.preprod.ebsi.eu/trusted-schemas-registry/v1/schemas/0xb77f8516a965631b4f197ad54c65a9e2f9936ebfb76bae4906d33744dbcc60ba",
    "type" : "FullJsonSchemaValidator2021"
  },
  "credentialSubject" : {
    "currentAddress" : [ "1 Boulevard de la Liberté, 59800 Lille" ],
    "dateOfBirth" : "1993-04-08",
    "familyName" : "DOE",
    "firstName" : "Jane",
    "gender" : "FEMALE",
    "id" : "did:iota:HxR45dSUrnt4BLZCUd8YzHCgWjrRBc8qhT3Nfr7T8zik",
    "nameAndFamilyNameAtBirth" : "Jane DOE",
    "personalIdentifier" : "0904008084H",
    "placeOfBirth" : "LILLE, FRANCE"
  },
  "evidence" : [ {
    "documentPresence" : [ "Physical" ],
    "evidenceDocument" : [ "Passport" ],
    "subjectPresence" : "Physical",
    "type" : [ "DocumentVerification" ],
    "verifier" : "did:ebsi:2A9BZ9SUe6BatacSpvs1V5CdjHvLpQ7bEsi2Jb6LdHKnQxaN"
  } ],
  "id" : "urn:uuid:615fdc7b-b0b0-4a65-9630-4264dc9f24d5",
  "issued" : "2022-09-07T15:22:43Z",
  "issuer" : "did:iota:HxR45dSUrnt4BLZCUd8YzHCgWjrRBc8qhT3Nfr7T8zik",
  "validFrom" : "2022-09-07T15:22:43Z",
  "issuanceDate" : "2022-09-07T15:22:43Z",
  "type" : [ "VerifiableCredential", "VerifiableAttestation", "VerifiableId" ],
  "proof" : {
    "type" : "JcsEd25519Signature2020",
    "created" : "2022-09-07T15:22:43Z",
    "domain" : "https://api.preprod.ebsi.eu",
    "proofPurpose" : "assertionMethod",
    "verificationMethod" : "did:iota:HxR45dSUrnt4BLZCUd8YzHCgWjrRBc8qhT3Nfr7T8zik#4090494cad68423db10149ae4febb928",
    "signatureValue" : "3wvVjULVKmAD5RT6jtTEQgkNVisXR5sxjX9bZP2LhBfrcGL3Z15cUuTVNR4FqvHgKZvp8p8dKWfCnqDk342yVvLD"
  }
}
"#;

          let valid = validate_credential(String::from(vc));

    }

    // #[test]
    // fn test_issue_and_validate_credential() {
    //     let cred = issue_credential();
    //     let valid = validate_credential(cred.unwrap());
    //     println!("Valid: {}", valid);
    // }

    #[test]
    fn test_publish_did() {

    }
}

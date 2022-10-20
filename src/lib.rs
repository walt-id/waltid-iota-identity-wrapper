#[macro_use]
extern crate lazy_static;

use std::{ffi::{CString, CStr}, os::raw::c_char, slice, ptr::{null_mut}, fmt::{format, Debug}};
use identity_iota::{account::{Account, IdentitySetup, MethodContent}, iota_core::IotaDID, prelude::{KeyPair, KeyType, IotaDocument}, core::{ToJson, FromJson}, client::{Resolver, CredentialValidator, FailFast, CredentialValidationOptions}, did::MethodRelationship, crypto::{Ed25519, PublicKey}, credential::Credential};
use tokio::runtime::Runtime;
use uuid::Uuid;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

#[no_mangle]
pub extern fn create_did(priv_key: *const u8, key_len: usize) -> *mut c_char {
    let account =  RUNTIME.block_on(
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
    println!("Creating did:iota...");
    let mut account = Account::builder().create_identity(identity_setup).await?;
    println!("Created did: {}", account.did().to_string());

    let signing_method = account.document().default_signing_method().unwrap();
    println!("Default signing method: {}", signing_method.to_json_pretty().unwrap());
    let fragment0 = signing_method.id().fragment().unwrap().to_string();
    let fragment1 = Uuid::new_v4().as_simple().to_string();
    let pub_key = PublicKey::from(signing_method.data().try_decode().unwrap());
    println!("Creating generic verification method ({}#{})...", signing_method.id().did().to_string(), fragment1);
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

async fn resolve_did_async(did_str: String) -> Result<IotaDocument, identity_iota::account::Error> {
    let resolver: Resolver = Resolver::new().await?;
    let did: IotaDID = IotaDID::parse(did_str)?;
    let doc = resolver.resolve(&did).await?;
    Ok(doc.document)
}

async fn validate_credential_async(credential_json: String) -> Result<bool, identity_iota::account::Error> {    
    let credential: Credential = Credential::from_json(credential_json.as_str())?;
    
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

#[no_mangle]
pub extern fn free_str(str: *mut i8) {
    // retake pointer to free memory
    let _ = unsafe { CString::from_raw(str) };
}

#[cfg(test)]
mod tests {
    use std::{ffi::{CStr, CString}, ptr::{null, null_mut}, slice};

    use identity_iota::{prelude::{KeyPair, KeyType}, client::Resolver};

    use crate::{create_did, resolve_did, free_str, validate_credential};

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
        let did_raw = CString::new("did:iota:HYPfLqscBJLRtGJfDatrbFQeC8unAFEuf7qth6SMJJUJ").unwrap().into_raw();
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
              "id" : "did:iota:HYPfLqscBJLRtGJfDatrbFQeC8unAFEuf7qth6SMJJUJ",
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
            "id" : "urn:uuid:8793f5d4-4db1-4c6d-ba00-01a208a49f5a",
            "issued" : "2022-10-13T13:23:37Z",
            "issuer" : "did:iota:HYPfLqscBJLRtGJfDatrbFQeC8unAFEuf7qth6SMJJUJ",
            "validFrom" : "2022-10-13T13:23:37Z",
            "issuanceDate" : "2022-10-13T13:23:37Z",
            "type" : [ "VerifiableCredential", "VerifiableAttestation", "VerifiableId" ],
            "proof" : {
              "type" : "JcsEd25519Signature2020",
              "creator" : "did:iota:HYPfLqscBJLRtGJfDatrbFQeC8unAFEuf7qth6SMJJUJ",
              "created" : "2022-10-13T13:23:38Z",
              "proofPurpose" : "assertionMethod",
              "verificationMethod" : "did:iota:HYPfLqscBJLRtGJfDatrbFQeC8unAFEuf7qth6SMJJUJ#ff01ea87141146a9b65cdebaa3d14995",
              "signatureValue" : "yjxL43PPrZBscMihcEciM53RyHjakp7n95djZTts2c4F6mEMPgti9s4J1ymdweh5U5Vqw72zXo1Nno9reVtw1vf"
            }
          }          
          "#;

          let valid = validate_credential(String::from(vc));
          assert_eq!(true, valid);
    }
}

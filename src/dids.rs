use std::slice;
use identity_account::account::Account;
use identity_account::types::{IdentitySetup, MethodContent};
use identity_account_storage::storage::Storage;
use identity_core::convert::ToJson;
use identity_core::crypto::{KeyPair, KeyType, PublicKey};
use identity_did::verification::{MethodRelationship, MethodScope};
use identity_iota_core::did::IotaDID;
use identity_iota_core::document::{IotaDocument, IotaVerificationMethod};
use uuid::Uuid;
use crate::store::WaltStore;

pub async fn create_account_async(priv_key: *const u8, key_len: usize) -> Result<IotaDocument, identity_account::Error> {
    let mut identity_setup = IdentitySetup::default();
    if !priv_key.is_null() && key_len > 0 {
        let kp = unsafe {
            KeyPair::try_from_private_key_bytes(
                KeyType::Ed25519,
                slice::from_raw_parts(priv_key, key_len))
        }.unwrap();
        let pk: Box<[u8]> = kp.private().as_ref().into();
        identity_setup = identity_setup.private_key(pk.into());
    }
    println!("Creating did:iota...");
    let mut account: Account = Account::builder().create_identity(identity_setup).await?;
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
    Ok(account.document().clone())
}

pub fn create_did(keyPair: &KeyPair) -> Result<IotaDocument, identity_account::Error> {
    println!("Creating did:iota offline");
    let mut document = IotaDocument::new(keyPair)?;
    let signing_method = document.default_signing_method()?.clone();
    println!("Default signing method: {}", signing_method.to_json_pretty()?);
    let fragment1 = Uuid::new_v4().as_simple().to_string();
    println!("Creating generic verification method ({}#{})...", signing_method.id().did().to_string(), fragment1);
    let vm = IotaVerificationMethod::new(document.id().clone(), keyPair.type_(), keyPair.public(), fragment1.as_str())?;
    document.insert_method(vm.clone(), MethodScope::VerificationMethod)?;
    document.attach_method_relationship(vm.id(), MethodRelationship::AssertionMethod)?;
    document.attach_method_relationship(vm.id(), MethodRelationship::Authentication)?;
    document.attach_method_relationship(vm.id(), MethodRelationship::CapabilityDelegation)?;
    document.attach_method_relationship(vm.id(), MethodRelationship::CapabilityInvocation)?;
    document.attach_method_relationship(vm.id(), MethodRelationship::KeyAgreement)?;
    document.remove_method(signing_method.id())?;
    Ok(document)
}

pub async fn publish_did(iotaDocument: &IotaDocument) -> Result<(), identity_account::Error> {
    let store = WaltStore::new();
    store.document_set(iotaDocument.id(), iotaDocument);
    let mut account: Account = Account::builder().storage(store).load_identity(iotaDocument.id().clone()).await?;
    account.publish().await
}


pub async fn resolve_did_async(did_str: String) -> Result<IotaDocument, identity_account::Error> {
    let resolver: Resolver = Resolver::new().await?;
    let did: IotaDID = IotaDID::parse(did_str)?;
    let doc = resolver.resolve(&did).await?;
    Ok(doc.document)
}
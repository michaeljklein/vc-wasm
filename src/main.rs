use wasmer::{Store, Module, Instance, Value, imports};

use chrono::{prelude::*};

use ssi::did::example::DIDExample;
use ssi::vc::Credential;
use ssi::vc::LinkedDataProofOptions;
use ssi::jwk::JWK;
use ssi::vc::VCDateTime;
use ssi::vc::URI;

fn main_wasmer() -> anyhow::Result<()> {
    let module_wat = r#"
    (module
    (type $t0 (func (param i32) (result i32)))
    (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
        get_local $p0
        i32.const 1
        i32.add))
    "#;

    let store = Store::default();
    let module = Module::new(&store, &module_wat)?;

    // The module doesn't import anything, so we create an empty import object.
    let import_object = imports! {};
    let instance = Instance::new(&module, &import_object)?;

    let add_one = instance.exports.get_function("add_one")?;
    let result = add_one.call(&[Value::I32(42)])?;
    assert_eq!(result[0], Value::I32(43));

    Ok(())
}

fn main_wasm_test() {
    match main_wasmer() {
        Err(e) => println!("error: {}", e),
        Ok(()) => println!("successful!"),
    }

    println!("Hello, world!!");
}




const JWK_JSON: &str = include_str!("../rsa2048-2020-08-25.json");

pub async fn decode_verify_jwt() {
    let key: JWK = serde_json::from_str(JWK_JSON).unwrap();

    let vc_str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.org/credentials/192783",
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": "2020-08-25T11:26:53Z",
        "credentialSubject": {
            "id": "did:example:a6c78986cc36418b95a22d7f736",
            "spouse": "Example Person"
        }
    }"###;

    let vc = Credential {
        expiration_date: Some(VCDateTime::from(Utc::now() + chrono::Duration::weeks(1))),
        ..serde_json::from_str(vc_str).unwrap()
    };
    let aud = "did:example:90336644520443d28ba78beb949".to_string();
    let options = LinkedDataProofOptions {
        domain: Some(aud),
        checks: None,
        created: None,
        verification_method: Some(URI::String("did:example:foo#key1".to_string())),
        ..Default::default()
    };
    let signed_jwt = vc
        .generate_jwt(Some(&key), &options, &DIDExample)
        .await
        .unwrap();
    println!("{:?}", signed_jwt);

    let (vc1_opt, verification_result) =
        Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
    println!("{:#?}", verification_result);
    assert!(verification_result.errors.is_empty());
    let vc1 = vc1_opt.unwrap();
    assert_eq!(vc.id, vc1.id);

    // // Test expiration date (ie make fail)
    // let vc = Credential {
    //     expiration_date: Some(VCDateTime::from(Utc::now() - chrono::Duration::weeks(1))),
    //     ..vc
    // };
    // let signed_jwt = vc
    //     .generate_jwt(Some(&key), &options, &DIDExample)
    //     .await
    //     .unwrap();
    // let (_vc_opt, verification_result) =
    //     Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
    // println!("{:#?}", verification_result);
    // assert!(verification_result.errors.len() > 0);
}


#[tokio::main]
pub async fn main() {
    let vc_str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.org/credentials/192783",
        "type": "VerifiableCredential",
        "issuer": "did:example:foo",
        "issuanceDate": "2020-08-25T11:26:53Z",
        "credentialSubject": {
            "id": "did:example:a6c78986cc36418b95a22d7f736",
            "spouse": "Example Person"
        }
    }"###;

    let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
    let vc: Credential = serde_json::from_str(vc_str).unwrap();
    let aud = "did:example:90336644520443d28ba78beb949".to_string();
    let options = LinkedDataProofOptions {
        domain: Some(aud),
        checks: None,
        created: None,
        ..Default::default()
    };
    let resolver = &DIDExample;
    let signed_jwt = vc
        .generate_jwt(Some(&key), &options, resolver)
        .await
        .unwrap();
    println!("{:?}", signed_jwt);

    let (vc_opt, verification_result) =
        Credential::decode_verify_jwt(&signed_jwt, Some(options.clone()), &DIDExample).await;
    println!("{:#?}", verification_result);
    let _vc = vc_opt.unwrap();
    assert_eq!(verification_result.errors.len(), 0);

    println!("Issuance complete!");

    main_wasm_test();

    decode_verify_jwt().await;

    println!("Verification complete!");
}


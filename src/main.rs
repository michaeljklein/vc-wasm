// use std::io::stdout;
use std::process::{Child, Command};
use std::fs::File;
use std::io::Write;


use std::thread::sleep;
use std::time::Duration;
use std::os::unix::net::{UnixListener, UnixStream};
use qapi::{qmp, Qmp};


use chrono::{prelude::*};

use ssi::did::example::DIDExample;
use ssi::vc::Credential;
use ssi::vc::LinkedDataProofOptions;
use ssi::jwk::JWK;
use ssi::vc::VCDateTime;
use ssi::vc::URI;

use wasmer::{Store, Module, Instance, Value, imports};


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


    let output = if cfg!(target_os = "macos") {
        Command::new("sh")
            .arg("-c")
            .arg("echo hello")
            .output()
            .map_err(|err| format!("command failed with error:\n{}", err))
            .and_then(|x|
                String::from_utf8(x.stdout)
                .map_err(|err| format!("non-utf8 output:\n{}", err)))

    } else {
        Err("untested except on target_os = macos".to_string())
    };

    println!("OK\n{:?}!", output);

    match std::fs::remove_file(QMP_SOCKET_PATH) {
        Err(err) => println!("error cleaning up socket:\n{}", err),
        Ok(()) => println!("cleaned up previous socket."),
    }

    match set_qemu_qmp_conf_socket(QMP_SOCKET_PATH.to_string()) {
        Err(err) => println!("error setting up qemu-qmp.conf:\n{}", err),
        Ok(()) => println!("qemu-qmp.conf setup."),
    }

    match qemu_system_version_check() {
        Err(err) => println!("version error:\n{}", err),
        Ok(()) => println!("qemu-system-x86_64 found."),
    }

    ::env_logger::init();


    let listener = UnixListener::bind(QMP_SOCKET_PATH).expect("could not bind socket");
    println!("bound socket");

    println!("running qemu..");
    let qemu_child_process = run_qemu().expect("failed to run qemu");
    println!("qemu running");

    // let socket_addr = args().nth(1).expect("argument: QMP socket path");
    // let stream = UnixStream::connect(socket_addr).expect("failed to connect to socket");
    let stream = UnixStream::connect(QMP_SOCKET_PATH).expect("failed to connect to socket");
    println!("connected to socket");

    let mut qmp = Qmp::from_stream(&stream);
    println!("QMP init");

    let info = qmp.handshake().expect("handshake failed");
    println!("QMP info: {:#?}", info);

    let status = qmp.execute(&qmp::query_status { }).unwrap();
    println!("VCPU status: {:#?}", status);

    loop {
        qmp.nop().unwrap();
        for event in qmp.events() {
            println!("Got event: {:#?}", event);
        }

        sleep(Duration::from_secs(1));
    }


}


pub fn run_qemu() -> Result<Child, String> {
    // NOTE: turn off pretty=on to un-pretty json
    let qemu_command = format!("
        qemu-system-x86_64 \\
            -m 512 \\
            -nic user \\
            -hda alpine.qcow2 \\
            -boot d \\
            -cdrom alpine-standard-3.16.1-x86_64.iso \\
            -chardev socket,id=qmp,path={},server=on,wait=off \
            -mon chardev=qmp,mode=control,pretty=on \
            -nographic | tee qemu-tee.log
    ", QMP_SOCKET_PATH);
            // -qmp-pretty ./qemu-qmp-socket \\
            // -readconfig qemu-qmp.conf \\

    println!("command:\n{}", qemu_command);



    let output = if cfg!(target_os = "macos") {
        Command::new("sh")
            .arg("-c")
            .arg(qemu_command)
            .spawn()
            .map_err(|err| format!("command failed with error:\n{}", err))
            // .and_then(|x|
            //     String::from_utf8(x.stdout)
            //     .map_err(|err| format!("non-utf8 output:\n{}", err)))
    } else {
        Err("untested except on target_os = macos".to_string())
    }?;

    Ok(output)
}



pub fn qemu_system_version_check() -> Result<(), String> {
    let output = if cfg!(target_os = "macos") {
        Command::new("sh")
            .arg("-c")
            .arg("qemu-system-x86_64 --version")
            .output()
            .map_err(|err| format!("command failed with error:\n{}", err))
            .and_then(|x|
                String::from_utf8(x.stdout)
                .map_err(|err| format!("non-utf8 output:\n{}", err)))
    } else {
        Err("untested except on target_os = macos".to_string())
    }?;

    match output.lines().next() {
        None => Err("no output from qemu-system-x86_64!".to_string()),
        Some(output_first_line) => {
            if output_first_line == "QEMU emulator version 7.0.0" {
                Ok(())
            } else {
                Err(format!("unexpected version line:\n{:?}", output_first_line))
            }
        },
    }
}





// use std::old_io::net::pipe::UnixListener;

pub static QMP_SOCKET_PATH: &'static str = "qemu-qmp-socket";

// fn main() {
//     let socket = Path::new(SOCKET_PATH);

//     // Delete old socket if necessary
//     if socket.exists() {
//         fs::unlink(&socket).unwrap();
//     }

//     // Bind to socket
//     let stream = match UnixListener::bind(&socket) {
//         Err(_) => panic!("failed to bind socket"),
//         Ok(stream) => stream,
//     };



pub fn set_qemu_qmp_conf_socket(socket_path: String) -> Result<(), String> {
    let mut f = File::create("qemu-qmp.conf")
        .map_err(|err| format!("error creating file:\n{}", err))?;

    let qemu_qmp_conf_str = format!(r#"
        # NOTE: This file is generated by vc-wasm and any changes will be
        # overwritten when it's run!

        [chardev "qmp"]
          backend = "socket"
          path = {:?}
          server = "on"
          wait = "off"
        [mon "qmp"]
          mode = "control"
          chardev = "qmp"
          pretty = "on"
    "#, socket_path);

    f.write_all(qemu_qmp_conf_str.as_bytes())
        .map_err(|err| format!("error creating file:\n{}", err))?;
    f.sync_all()
        .map_err(|err| format!("error creating file:\n{}", err))?;
    Ok(())
}

// 2. Add the following sections to your QEMU config file (or create a qemu-qmp.conf one):



// use std::os::unix::net::UnixStream;

// use std::fs;

// fn main() {
//     let data = fs::read_to_string("/etc/hosts").expect("Unable to read file");
//     println!("{}", data);
// }
// Read a file as a Vec<u8>
// use std::fs;

// fn main() {
//     let data = fs::read("/etc/hosts").expect("Unable to read file");
//     println!("{}", data.len());
// }
// Write a file

// fn main() {
//     let data = "Some data!";
//     fs::write("/tmp/foo", data).expect("Unable to write file");
// }





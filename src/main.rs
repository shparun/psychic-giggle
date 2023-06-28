use base64::prelude::BASE64_STANDARD;
use base64::write::EncoderWriter;
use reqwest::blocking::ClientBuilder;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    ClientConnection,
};

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

#[allow(unused)]
#[derive(Debug)]
struct Certificate {
    is_ca: bool,
    issuer: String,
    subject: String,
    validity: String,
    thumbprint: String,
}

fn describe(cert: &rustls::Certificate) -> Result<Certificate, x509_parser::prelude::X509Error> {
    use sha1::{Digest, Sha1};
    use x509_parser::prelude::*;

    fn to_hex_string(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        write_lower_hex(&mut s, bytes);
        s
    }

    fn write_lower_hex(f: &mut impl std::fmt::Write, bytes: &[u8]) {
        for b in bytes {
            write!(f, "{:02x}", b).expect("failed to format byte");
        }
    }

    let mut hasher = Sha1::new();
    hasher.update(&cert.0);
    let thumbprint = hasher.finalize();
    let thumbprint_hex = to_hex_string(&thumbprint);
    let (_, cert) = parse_x509_certificate(&cert.0)?;

    Ok(Certificate {
        is_ca: cert.is_ca(),
        issuer: cert.tbs_certificate.issuer().to_string(),
        subject: cert.tbs_certificate.subject().to_string(),
        validity: format!(
            "{:?} to {:?}",
            cert.tbs_certificate.validity().not_before,
            cert.tbs_certificate.validity().not_after
        ),
        thumbprint: thumbprint_hex,
    })
}

fn peer_certificates(
    connection: &rustls::ClientConnection,
) -> Vec<Result<Certificate, x509_parser::prelude::X509Error>> {
    return if let Some(peer_certificates) = connection.peer_certificates() {
        peer_certificates
            .into_iter()
            .map(|cert| describe(cert))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
}

fn main() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Debug)
        .init();

    let domain = "jetbrains.com";
    let url = format!("https://{}", domain);

    let certs = rustls_native_certs::load_native_certs()
        .expect("unable to load native certs")
        .into_iter()
        .map(|it| describe(&rustls::Certificate(it.0)))
        .collect::<Vec<_>>();

    println!(
        "Root certificates loaded by rustls_native_certs: {:#?}",
        certs
    );
    println!("=======================================================");
    println!("TRUSTING RUSTLS CLIENT");
    let dangerous_client = ClientBuilder::new()
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    dangerous_client.get(&url).send().unwrap();
    println!("=======================================================");
    println!("RUSTLS CLIENT");

    let client = ClientBuilder::new().use_rustls_tls().build().unwrap();
    match client.get(&url).send() {
        Ok(response) => {
            println!("reqwest response from {}: {:#?}", url, response);
        }
        Err(err) => {
            println!("reqwest returns een error for {}: {:#?}", url, err);
        }
    }

    println!("=======================================================");
    println!("NATIVE CLIENT");

    let client = ClientBuilder::new().use_native_tls().build().unwrap();
    match client.get(&url).send() {
        Ok(response) => {
            println!("reqwest response from {}: {:#?}", url, response);
        }
        Err(err) => {
            println!("reqwest returns een error for {}: {:#?}", url, err);
        }
    }
}

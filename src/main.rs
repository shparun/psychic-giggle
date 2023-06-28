use base64::prelude::BASE64_STANDARD;
use base64::write::EncoderWriter;
use reqwest::blocking::ClientBuilder;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    ClientConnection,
};
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};
use x509_parser::prelude::*;

#[allow(unused)]
#[derive(Debug)]
struct Certificate {
    issuer: String,
    subject: String,
    validity: String,
    thumbprint: String,
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    write_lower_hex(&mut s, bytes);
    s
}

fn write_lower_hex(f: &mut impl std::fmt::Write, bytes: &[u8]) {
    for b in bytes {
        write!(f, "{:02x}", b).expect("failed to format byte");
    }
}

fn describe(cert: &rustls::Certificate) -> Result<Certificate, X509Error> {
    let mut hasher = Sha1::new();
    hasher.update(&cert.0);
    let thumbprint = hasher.finalize();
    let thumbprint_hex = to_hex_string(&thumbprint);
    let (_, cert) = parse_x509_certificate(&cert.0)?;
    Ok(Certificate {
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

struct NoopVerifier;

impl ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn trusting_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoopVerifier))
        .with_no_client_auth()
}

fn peer_certificates(connection: &rustls::ClientConnection) -> Vec<Result<Certificate, X509Error>> {
    return if let Some(peer_certificates) = connection.peer_certificates() {
        peer_certificates
            .into_iter()
            .map(|cert| describe(cert))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
}

struct Proxy;

fn https_proxy_from_env() -> Option<Proxy> {
    todo!()
}

fn basic_auth<U, P>(username: U, password: Option<P>) -> String
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{}:", username);
        if let Some(password) = password {
            let _ = write!(encoder, "{}", password);
        }
    }
    String::from_utf8(buf).unwrap()
}

fn main() {
    let domain = "jetbrains.com";

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

    if let Some(proxy) = https_proxy_from_env() {
        todo!()
    } else {
        let server = rustls::ServerName::try_from(domain).expect("invalid DNS name");
        let mut tcp = TcpStream::connect(format!("{}:443", domain)).unwrap();
        let server = rustls::ServerName::try_from(domain).expect("invalid DNS name");
        let mut connection =
            rustls::ClientConnection::new(Arc::new(trusting_config()), server).unwrap();
        let mut stream = rustls::Stream::new(&mut connection, &mut tcp);

        stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut plaintext = Vec::new();
        stream.read_to_end(&mut plaintext).unwrap();
        let domain_peer_certificates = peer_certificates(&connection);
        println!(
            "Peer certificates of {domain}: {:#?}",
            domain_peer_certificates
        );
    }

    println!("=======================================================");

    let builder = ClientBuilder::new().danger_accept_invalid_certs(true);
    let client = builder.build().unwrap();
    let url = format!("https://{}", domain);
    match client.get(&url).send() {
        Ok(response) => {
            println!("reqwest response from {}: {:#?}", url, response);
        }
        Err(err) => {
            println!("reqwest returns een error for {}: {:#?}", url, err);
        }
    }
}

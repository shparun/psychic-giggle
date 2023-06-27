use reqwest::blocking::ClientBuilder;
use x509_parser::prelude::*;

#[allow(unused)]
#[derive(Debug)]
struct Certificate {
    issuer: String,
    subject: String,
    validity: String,
}

fn main() {
    let certs = rustls_native_certs::load_native_certs().expect("unable to load native certs");

    for bytes in certs {
        let cert = rustls::Certificate(bytes.0);
        match parse_x509_certificate(&cert.0) {
            Ok((_, cert)) => {
                let pretty = Certificate {
                    issuer: cert.tbs_certificate.issuer().to_string(),
                    subject: cert.tbs_certificate.subject().to_string(),
                    validity: format!(
                        "{:?} to {:?}",
                        cert.tbs_certificate.validity().not_before,
                        cert.tbs_certificate.validity().not_after
                    ),
                };
                println!("{:#?}", pretty);
            }
            Err(err) => {
                println!("Failed to parse certificate: {:?}", err);
            }
        }
    }

    let builder = ClientBuilder::new();
    let client = builder.build().unwrap();
    let url = "https://jetbrains.com";
    let response = client.get(url).send();
    print!("response from {}: {:#?}", url, response);
}

// extern crate rustls;
// extern crate ring;
// extern crate data_encoding;
extern crate untrusted;
extern crate openssl;

use openssl::asn1::Asn1Time;
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;
use openssl::x509::{X509, X509Name};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::ec::{EcGroup, EcPoint, EcKey};
use openssl::nid::Nid;

use openssl::base64;

// import other modules
mod seclevel;
mod args;

use crate::args::parse_args;
use crate::seclevel::{CertEntity, SecLib, SecLibI};


fn main() {
    let _args = parse_args();

    // let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    // let ec_priv = EcKey::generate(group.as_ref()).unwrap();
    // let ec_publ = ec_priv.public_key();
    // // let mut ctx = BigNumContext::new().unwrap();
    // // let point = EcPoint::new(&group).unwrap();

    // let rsa = Rsa::generate(2048).unwrap();

    // // let ec = EcKey::from_curve_name(Nid::SECP256K1).unwrap();
    // // let ec_key = EcKey::from_private_components(
    // //     ec.group(), ec.private_key(), ec.public_key()).unwrap();
    // // let pkey = PKey::from_rsa(rsa).unwrap();
    // let ec_pkey = PKey::from_ec_key(ec_priv).unwrap();

    // let mut name = X509Name::builder().unwrap();
    // name.append_entry_by_nid(Nid::ORG,
    //                          "INESC-ID").unwrap();
    // name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME,
    //                          "GSD").unwrap();
    // name.append_entry_by_nid(Nid::STATEORPROVINCENAME,
    //                          "Lisbon").unwrap();
    // name.append_entry_by_nid(Nid::COUNTRYNAME,
    //                          "PT").unwrap();
    // name.append_entry_by_nid(Nid::common_name,
    //                          "foobar.com").unwrap();
    // let name = name.build();

    // let serialNumber = BigNum::from_u32(1234).unwrap();
    // let asn1Serial = Asn1Integer::from_bn(serialNumber.as_ref()).unwrap();

    // let mut builder = X509::builder().unwrap();
    // builder.set_version(2).unwrap();
    // builder.set_subject_name(&name).unwrap();
    // builder.set_issuer_name(&name).unwrap();
    // builder.set_serial_number(asn1Serial.as_ref()).unwrap();
    // builder.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref()).unwrap();
    // builder.set_not_after(Asn1Time::days_from_now(9999).unwrap().as_ref()).unwrap();
    // builder.set_pubkey(&ec_pkey).unwrap();
    // builder.sign(&ec_pkey, MessageDigest::sha3_512()).unwrap();

    // let pem = builder.build().to_pem().unwrap();
    // pem.
    let entity = CertEntity {
        org : "INESC-ID".to_string(),
        org_unit : "GSD".to_string(),
        country : "PT".to_string(),
        province : "Lisbon".to_string(),
        location : "Lisbon".to_string(),
        common_name : "gsd.inesc-id.pt".to_string(),
    };
    let sec = SecLib::new();
    let cert = sec.create_self_signed_cert(1234, entity);
    println!("{}", String::from_utf8(cert.bytes).unwrap());

    // let certificate: X509 = builder.build();
    //
    // // Generate a key pair in PKCS#8 (v2) format.
    // let rng = rand::SystemRandom::new();
    // let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    // let pkcs8_bytes2 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    //
    // // Normally the application would store the PKCS#8 file persistently. Later
    // // it would read the PKCS#8 file from persistent storage to use it.
    //
    // let key_pair = signature::Ed25519KeyPair::from_pkcs8(
    //     pkcs8_bytes.as_ref()).unwrap();
    // let key_pair2 = signature::Ed25519KeyPair::from_pkcs8(
    //     pkcs8_bytes2.as_ref()).unwrap();
    //
    // // Sign the message "hello, world".
    // const MESSAGE: &[u8] = b"hello, world";
    // let sig = key_pair.sign(MESSAGE);
    //
    // // Normally an application would extract the bytes of the signature and
    // // send them in a protocol message to the peer(s). Here we just get the
    // // public key key directly from the key pair.
    // let peer_public_key_bytes = key_pair.public_key().as_ref();
    // let peer_public_key2_bytes = key_pair2.public_key().as_ref();
    //
    // println!("public key: {}", BASE64.encode(peer_public_key_bytes));
    // println!("signature : {}", BASE64.encode(sig.as_ref()));
    //
    // // Verify the signature of the message using the public key. Normally the
    // // verifier of the message would parse the inputs to this code out of the
    // // protocol message(s) sent by the signer.
    // let peer_public_key =
    //     signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
    // let peer_public_key2 =
    //     signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key2_bytes);
    //
    // let valid = || -> Result<(), Unspecified> {
    //     peer_public_key.verify(MESSAGE, sig.as_ref())?;
    //     println!("isValid   : {}", true);
    //     Ok(())
    // };
    // if let Err(_err) = valid() {
    //     println!("isValid   : {} ({})", false, _err);
    // }
    //
    // // now tries with other key
    // let valid = || -> Result<(), Unspecified> {
    //     peer_public_key2.verify(MESSAGE, sig.as_ref())?;
    //     println!("isValid   : {}", true);
    //     Ok(())
    // };
    // if let Err(_err) = valid() {
    //     println!("isValid   : {} ({})", false, _err);
    // }

}

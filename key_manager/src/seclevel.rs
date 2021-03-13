extern crate openssl;

use openssl::nid::Nid;
// use openssl::aes::{AesKey, aes_ige};
// use openssl::symm::Mode;
use openssl::hash::MessageDigest;
use openssl::ec::{EcGroup, EcKey, EcPointRef};
use openssl::pkey::{PKey, Public, Private};
use openssl::x509::{X509Name, X509};
use openssl::bn::BigNum;
use openssl::asn1::{Asn1Integer, Asn1Time};

const SECLEVEL_ECC_NID_LOW : Nid = Nid::SECP160K1;
const SECLEVEL_ECC_NID_MID : Nid = Nid::SECP384R1;
const SECLEVEL_ECC_NID_HIG : Nid = Nid::SECP521R1;

#[derive(Clone)]
pub struct CertEntity {
    pub org : String,
    pub org_unit : String,
    pub country : String,
    pub province : String,
    pub location : String,
    pub common_name : String,
}

#[derive(Clone)]
pub struct Cert {
    pub issuer : CertEntity,
    pub subject : CertEntity,
    pub bytes : Vec<u8>,
}

pub trait SecLibI {
    fn short_hash(&self) -> MessageDigest;
    fn long_hash(&self) -> MessageDigest;
    fn create_self_signed_cert(&self, days_valid : u32, entity : CertEntity) -> Cert;
    fn create_signed_cert(&self, issuer : Cert, days_valid : u32, subject : CertEntity) -> Cert;
}

pub struct SecLib {
    nonce : u32,
    sign_strength : Nid,
}

trait SecLibCurveI { }

struct SecLibCurve {
    ec_key : EcGroup,
    ec_priv : EcKey<Private>,
    ec_publ : EcKey<Public>,
    ec_pkey : PKey<Private>, 
}

impl SecLibCurveI for SecLibCurve { }

trait SecLibInt {
    // internal, do not call
    fn i_setup_curve(&self, curve_type : Nid) ->  Box<SecLibCurve>;
    fn i_setup_name(&self, entity : CertEntity) -> X509Name;
}

impl SecLib {
    pub fn new() -> SecLib {
        SecLib {
            nonce : 1234567890,
            sign_strength : SECLEVEL_ECC_NID_MID,
        }
    }
}

impl SecLibInt for SecLib {
    fn i_setup_curve(&self, curve_type : Nid) -> Box<SecLibCurve> {
        let ec_key = EcGroup::from_curve_name(curve_type).unwrap();
        let ec_priv = EcKey::generate(ec_key.as_ref()).unwrap();
        let ec_publ = EcKey::from_public_key(ec_key.as_ref(), ec_priv.public_key()).unwrap();
        let ec_pkey = PKey::from_ec_key(ec_priv.clone()).unwrap();

        Box::new(SecLibCurve {
            ec_key : ec_key,
            ec_priv : ec_priv,
            ec_publ : ec_publ,
            ec_pkey : ec_pkey,
        })
    }
    fn i_setup_name(&self, entity : CertEntity) -> X509Name {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::ORG, entity.org.as_ref()).unwrap();
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, entity.org_unit.as_ref()).unwrap();
        name.append_entry_by_nid(Nid::STATEORPROVINCENAME, entity.province.as_ref()).unwrap();
        name.append_entry_by_nid(Nid::COUNTRYNAME, entity.country.as_ref()).unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, entity.common_name.as_ref()).unwrap();
        name.build()
    }
}

impl SecLibI for SecLib {

    fn short_hash(&self) -> MessageDigest {
        MessageDigest::sha256()
    }
    
    fn long_hash(&self) -> MessageDigest {
        MessageDigest::sha512()
    }
    
    fn create_self_signed_cert(&self, days_valid : u32, entity : CertEntity) -> Cert {
        let nonce = self.nonce;
        let hash_type = self.long_hash();
        let curve_type = self.sign_strength;
        
        let curve = self.i_setup_curve(curve_type);
        let name = self.i_setup_name(entity.clone());
        
        // let group = EcGroup::from_curve_name(curve_type).unwrap();
        // let ec_priv = EcKey::generate(group.as_ref()).unwrap();
        // let ec_publ = ec_priv.public_key();
        // let ec_pkey = PKey::from_ec_key(ec_priv).unwrap();
        
        // let mut name = X509Name::builder().unwrap();
        // name.append_entry_by_nid(Nid::ORG,
        //     entity.org.as_ref()).unwrap();
        // name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME,
        //     entity.org_unit.as_ref()).unwrap();
        // name.append_entry_by_nid(Nid::STATEORPROVINCENAME,
        //     entity.province.as_ref()).unwrap();
        // name.append_entry_by_nid(Nid::COUNTRYNAME,
        //     entity.country.as_ref()).unwrap();
        // name.append_entry_by_nid(Nid::COMMONNAME,
        //     entity.common_name.as_ref()).unwrap();
        // let name = name.build();
        
        let serialNumber = BigNum::from_u32(nonce).unwrap();
        let asn1Serial = Asn1Integer::from_bn(serialNumber.as_ref()).unwrap();
        
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_serial_number(asn1Serial.as_ref()).unwrap();
        builder.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref()).unwrap();
        builder.set_not_after(Asn1Time::days_from_now(days_valid).unwrap().as_ref()).unwrap();
        builder.set_pubkey(&(*curve).ec_pkey).unwrap();
        builder.sign(&curve.ec_pkey, hash_type).unwrap();
        
        let pem = builder.build().to_pem().unwrap();
        
        /*return*/ Cert {
            issuer : entity.clone(),
            subject : entity.clone(),
            bytes : pem,
        }
    }

    fn create_signed_cert(&self, issuer : Cert, days_valid : u32, subject : CertEntity) -> Cert {
        issuer
    }
}


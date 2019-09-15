use openssl::symm::*;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::error::ErrorStack;

// use mbedtls::cipher::{Cipher as CipherMbed, Encryption, Decryption, Authenticated, Fresh, AdditionalData};
// use mbedtls::cipher::raw::Cipher as CipherMbed;
// use mbedtls::cipher::raw;
// use mbedtls::cipher::raw::Operation;

use std::io::stdout;
use std::io::Write;

use packets::ip::Flow;
use packets::buffer;
use packets::TcpHeader;
use packets::ip::ProtocolNumbers;
use packets::ip::v4::Ipv4Header;
use std::net::{IpAddr, Ipv4Addr};
use std::cell::RefCell;


#[derive(Debug)]
pub enum CryptoError {
    HmacMismatch,
    PktlenError,
    AESEncryptError,
    AESDecryptError,
}

const AES_KEY: &[u8] = b"\x92\x65\x49\x29\x1f\x40\x1a\xcc\x98\x00\x77\x69\x13\xfd\xc0\x11";
const AES_IV: &[u8] = b"\x31\xa5\xcf\xe1\x05\x30\xb0\x2e\x9c\x5e\xeb\x31\x6f\x4e\x05\x01";
const SHA_KEY: &[u8] = b"\x8a\xcf\xe8\x19\x14\x87\x40\x59\x9d\xd0\xb1\xb1\x20\x1a\xf5\x15\
                  \x53\x1b\x0f\xbc\xf1\x38\xc1\x25\x4c\xf8\xc8\xae\x33\x6d\xc4\xbd";

pub const MAX_PKT_SIZE: usize = 65535;
pub const ESP_HEADER_LENGTH: usize = 8;
pub const AES_CBC_IV_LENGTH: usize = 16;
pub const ESP_HMAC_LEN: usize = 12;
pub const IP_HEADER_LENGTH: usize = 20;
pub const ICV_LEN_SHA256: usize = 16;

pub const AES_GCM_IV_LENGTH: usize = 16;
pub const ICV_LEN_GCM128: usize = 16;

thread_local! {
    pub static OPENSSL_SHA_DEC: RefCell<Crypter> = {
        let cipher = Cipher::aes_128_cbc();
        let mut c = Crypter::new(cipher, Mode::Decrypt, AES_KEY, Some(AES_IV)).unwrap();
        c.pad(false);
        RefCell::new(c)
    };
}

thread_local! {
    pub static OPENSSL_SHA_ENC: RefCell<Crypter> = {
        let cipher = Cipher::aes_128_cbc();
        let mut c = Crypter::new(cipher, Mode::Encrypt, AES_KEY, Some(AES_IV)).unwrap();
        c.pad(false);
        RefCell::new(c)
    };
}

#[inline]
pub fn my_decrypt_cbc(
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut out = vec![0; data.len() + 16];
    OPENSSL_SHA_DEC.with(|c_t| {
        let mut c = c_t.borrow_mut();
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    })
}

#[inline]
pub fn my_encrypt_cbc(
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut out = vec![0; data.len() + 16];
    OPENSSL_SHA_ENC.with(|c_t| {
        let mut c = c_t.borrow_mut();
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    })
}


// thread_local! {
//     pub static SHA_SIGNER_KEY: RefCell<PKey<Private>> = {
//         let key = PKey::hmac(SHA_KEY).unwrap();
//         RefCell::new(key)
//     };
// }

// thread_local! {
//     pub static SHA_SIGNER: RefCell<Signer<'static>> = {
//         SHA_SIGNER_KEY.with(|c_t| {
//             let c = c_t.borrow();
//             let mut signer = Signer::new(MessageDigest::sha256(), &c).unwrap();
//             RefCell::new(signer)
//         })
//     };
// }

// #[inline]
// pub fn my_sha_sign(
//     data: &[u8],
// ) -> Result<Vec<u8>, ErrorStack> {
//     SHA_SIGNER.with(|signer_t| {
//         let mut signer = signer_t.borrow_mut();
//         signer.update(data).unwrap();
//         let hmac = signer.sign_to_vec().unwrap();
//         Ok(hmac)
//     })   
// }

// pktptr points to the start of the cleartext ip header.
// after output, output points to the start of the ESP header
// This function will return outlen: u16
pub fn aes_cbc_sha256_encrypt_openssl(pktptr: &[u8], esphdr: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>
{
    let pktlen = pktptr.len();
    if (pktlen < 16) || (pktlen%16 != 0) {
        println!("Encrypt: packetlen is not proper");
        stdout().flush().unwrap();
        return Err(CryptoError::PktlenError);
    }
    if pktlen >(MAX_PKT_SIZE - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH - ICV_LEN_SHA256) as usize
    {
        println!("Packet is too big to handle");
        stdout().flush().unwrap();
        return Err(CryptoError::PktlenError);
    }
    output[..ESP_HEADER_LENGTH].copy_from_slice(esphdr);
    output[ESP_HEADER_LENGTH..(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH)].copy_from_slice(AES_IV);

    let ciphertext = my_encrypt_cbc(pktptr).unwrap();
    let ciphertext_len = ciphertext.len();
    output[(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH)..(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len)].copy_from_slice(&ciphertext[..]);
    if ciphertext_len != pktlen
    {
        println!("cleartext pktlen: {} vs. ciphertext pktlen: {}", pktptr.len(), ciphertext_len);
        println!("AES encryption errors");
        stdout().flush().unwrap();
        return Err(CryptoError::AESEncryptError);
    }
    let key = PKey::hmac(SHA_KEY).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&output[..(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len)]).unwrap();
    let hmac = signer.sign_to_vec().unwrap();
    // let hmac = my_sha_sign(&output[..(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len)]).unwrap();
    output[(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len)..(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len + ICV_LEN_SHA256)].copy_from_slice(&hmac[..ICV_LEN_SHA256]);
    
    Ok(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ciphertext_len + ICV_LEN_SHA256)
}

// pktptr points to the start of the ESP header
// after calling, output points to the start of the decrypted ip header.
// This function will return outlen: u16
pub fn aes_cbc_sha256_decrypt_openssl(pktptr: &[u8], output: &mut [u8], compdigest: bool) -> Result<usize, CryptoError> 
{
    let pktlen = pktptr.len();    
    if pktlen < (ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH + ICV_LEN_SHA256) {
        println!("Decrypt: Packet length is not proper");
        stdout().flush().unwrap();
        return Err(CryptoError::PktlenError);
    }
    let key = PKey::hmac(SHA_KEY).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&pktptr[..(pktlen - ICV_LEN_SHA256)]).unwrap();
    let hmac = signer.sign_to_vec().unwrap();
    // let hmac = my_sha_sign(&pktptr[..(pktlen - ICV_LEN_SHA256)]).unwrap();
    if compdigest
    {
        if !memcmp::eq(&hmac[..ICV_LEN_SHA256], &pktptr[(pktlen - ICV_LEN_SHA256)..])
        {
            println!("INBOUND Mac Mismatch");
            stdout().flush().unwrap();
            return Err(CryptoError::HmacMismatch);
        }
    }
    // let cipher = Cipher::aes_128_cbc();
    let cleartext = my_decrypt_cbc(&pktptr[(ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH)..(pktlen - ICV_LEN_SHA256)]).unwrap();
    
    let cleartext_len = cleartext.len();
    if cleartext_len != pktlen - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH - ICV_LEN_SHA256
    {
        println!("ciphertext pktlen: {} vs. cleartext pktlen: {}", pktlen - ESP_HEADER_LENGTH - AES_CBC_IV_LENGTH - ICV_LEN_SHA256, cleartext_len);
        println!("AES decryption errors");
        stdout().flush().unwrap();
        return Err(CryptoError::AESDecryptError);
    }
    output[..(cleartext_len)].copy_from_slice(&cleartext[..]);

    Ok(cleartext_len + ESP_HEADER_LENGTH + AES_CBC_IV_LENGTH)
}


thread_local! {
    pub static OPENSSL_GCM_DEC: RefCell<Crypter> = {
        let cipher = Cipher::aes_128_gcm();
        let mut c = Crypter::new(cipher, Mode::Decrypt, AES_KEY, Some(AES_IV)).unwrap();
        RefCell::new(c)
    };
}

thread_local! {
    pub static OPENSSL_GCM_ENC: RefCell<Crypter> = {
        let cipher = Cipher::aes_128_gcm();
        let mut c = Crypter::new(cipher, Mode::Encrypt, AES_KEY, Some(AES_IV)).unwrap();
        RefCell::new(c)
    };
}

#[inline]
pub fn my_decrypt_gcm(
    aad: &[u8],
    data: &[u8],
    tag: &[u8]
) -> Result<Vec<u8>, ErrorStack> {
    let mut out = vec![0; data.len() + 16];
    OPENSSL_GCM_DEC.with(|c_t| {
        let mut c = c_t.borrow_mut();
        c.aad_update(aad)?;
        let count = c.update(data, &mut out)?;
        c.set_tag(tag)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    })
}

#[inline]
pub fn my_encrypt_gcm(
    aad: &[u8],
    data: &[u8],
    tag: &mut [u8]
) -> Result<Vec<u8>, ErrorStack> {
    let mut out = vec![0; data.len() + 16];
    OPENSSL_GCM_ENC.with(|c_t| {
        let mut c = c_t.borrow_mut();
        // let cipher = Cipher::aes_128_gcm();
        // let mut c = Crypter::new(cipher, Mode::Encrypt, AES_KEY, Some(AES_IV)).unwrap();
        
        c.aad_update(aad)?;
        // println!("after aad_upate1");

        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        c.get_tag(tag)?;
        out.truncate(count + rest);
        Ok(out)
    })
}


pub fn aes_gcm128_encrypt_openssl(pktptr: &[u8], esphdr: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>
{
    let pktlen = pktptr.len();
    output[..ESP_HEADER_LENGTH].copy_from_slice(esphdr);
    output[ESP_HEADER_LENGTH..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)].copy_from_slice(AES_IV);
    let hmac: &mut [u8] = &mut [0u8; 16];

    let mut ciphertext_len = pktlen;
    if let Ok(ciphertext) = my_encrypt_gcm(&output[..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)], pktptr, hmac)
    {
        ciphertext_len = ciphertext.len();
        println!("{}", ciphertext_len);

        output[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + pktlen)..].copy_from_slice(hmac);
        output[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + ciphertext_len)].copy_from_slice(&ciphertext[..]);    
    }
    
    Ok(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + ciphertext_len + ICV_LEN_GCM128)
}


pub fn aes_gcm128_decrypt_openssl(pktptr: &[u8], output: &mut [u8], compdigest: bool) -> Result<usize, CryptoError>
{
    let pktlen = pktptr.len();
    // let hmac: &mut [u8] = &mut [0u8; 16];
    
    if let Ok(cleartext) = my_decrypt_gcm(&pktptr[0..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)], 
        &pktptr[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)..(pktlen - ICV_LEN_GCM128)], &pktptr[(pktlen - ICV_LEN_GCM128)..])
    {
        let cleartext_len = cleartext.len();
        println!("{}", cleartext_len);
        output[..(cleartext_len)].copy_from_slice(&cleartext[..]);
    }

    Ok(pktlen - ICV_LEN_GCM128)
}

// thread_local! {
//     pub static CIPHER_ENCRY: RefCell<CipherMbed> = {
//         let mut cipher = CipherMbed::setup(
//             raw::CipherId::Aes,
//             raw::CipherMode::GCM,
//             (AES_KEY.len() * 8) as u32,
//         ).unwrap();
//         cipher.set_key(Operation::Encrypt, AES_KEY).unwrap();
//         cipher.set_iv(AES_IV).unwrap();
//         RefCell::new(cipher)
//     };
// }


// thread_local! {
//     pub static CIPHER_DECRY: RefCell<CipherMbed> = {
//         let mut cipher = CipherMbed::setup(
//             raw::CipherId::Aes,
//             raw::CipherMode::GCM,
//             (AES_KEY.len() * 8) as u32,
//         ).unwrap();
//         cipher.set_key(Operation::Decrypt, AES_KEY).unwrap();
//         cipher.set_iv(AES_IV).unwrap();
//         RefCell::new(cipher)
//     };
// }


// pub fn aes_gcm128_encrypt_mbedtls(pktptr: &[u8], esphdr: &[u8], output: &mut [u8]) -> Result<usize, CryptoError>
// {
//     let pktlen = pktptr.len();
//     // if pktlen >(MAX_PKT_SIZE - ESP_HEADER_LENGTH - AES_GCM_IV_LENGTH - ICV_LEN_GCM128) as usize
//     // {
//     //     println!("Packet is too big to handle");
//     //     stdout().flush().unwrap();
//     //     return Err(CryptoError::PktlenError);
//     // }
//     let hmac: &mut [u8] = &mut [0u8; 16];
//     let aad: &mut [u8] = &mut [0u8; (ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)];
//     aad[..ESP_HEADER_LENGTH].copy_from_slice(esphdr);
//     aad[ESP_HEADER_LENGTH..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)].copy_from_slice(AES_IV);
    
//     CIPHER_ENCRY.with(|cipher| {
//         let mut cipher_lived = cipher.borrow_mut();
//         cipher_lived.encrypt_auth(aad, pktptr, 
//             &mut output[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + pktlen)], hmac).unwrap();
//     });
    
//     output[..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)].copy_from_slice(aad);
//     output[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + pktlen)..].copy_from_slice(hmac);
    
//     Ok(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + pktlen + ICV_LEN_GCM128)
// }

// pub fn aes_gcm128_decrypt_mbedtls(pktptr: &[u8], output: &mut [u8], compdigest: bool) -> Result<usize, CryptoError>
// {
//     let pktlen = pktptr.len();    
//     // if pktlen < (ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + ICV_LEN_GCM128) {
//     //     println!("Decrypt: Packet length is not proper");
//     //     stdout().flush().unwrap();
//     //     return Err(CryptoError::PktlenError);
//     // }
//     CIPHER_DECRY.with(|cipher| {
//         let mut cipher = cipher.borrow_mut();
//         if let Ok(_plain_text) = cipher.decrypt_auth(&pktptr[0..(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)], &pktptr[(ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH)..(pktlen - ICV_LEN_GCM128)],
//             &mut output[..(pktlen - (ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH + ICV_LEN_GCM128))], &pktptr[(pktlen - ICV_LEN_GCM128)..])
//         {
//             let cleartext_len = pktlen - ESP_HEADER_LENGTH - AES_GCM_IV_LENGTH - ICV_LEN_GCM128;
//             return Ok(cleartext_len + ESP_HEADER_LENGTH + AES_GCM_IV_LENGTH);
//         }
//         return Ok(pktlen - ICV_LEN_GCM128);  
//     })
// }


#[inline]
pub fn get_flow(pkt: &[u8]) -> Flow{
    unsafe {
        let ip_hdr: *const Ipv4Header = (&pkt[0] as *const u8) as *const Ipv4Header;
        let tcp_hdr: *const TcpHeader = (&pkt[0] as *const u8).offset(20) as *const TcpHeader;
        Flow::new(
            IpAddr::V4((*ip_hdr).src()),
            IpAddr::V4((*ip_hdr).dst()),
            (*tcp_hdr).src_port(),
            (*tcp_hdr).dst_port(),
            ProtocolNumbers::Tcp,
        )
    }
}


#[inline]
pub fn get_src_ip(pkt: &[u8]) -> Ipv4Addr{
    unsafe {
        let ip_hdr: *const Ipv4Header = (&pkt[0] as *const u8) as *const Ipv4Header;
        (*ip_hdr).src()
    }
}


#[inline]
pub fn set_dst_ip(pkt: &mut [u8], dst_ip: u32){
    unsafe {
        let ip_hdr: *mut Ipv4Header = (&mut pkt[0] as *mut u8) as *mut Ipv4Header;
        (*ip_hdr).set_dst(Ipv4Addr::new(((dst_ip >> 24) & 0xFF) as u8,
             ((dst_ip >> 16) & 0xFF) as u8, ((dst_ip >> 8) & 0xFF) as u8, (dst_ip & 0xFF) as u8));
    }
}


#[inline]
pub fn set_flow(pkt: &mut [u8], flow: Flow){
    unsafe {
        let ip_hdr: *mut Ipv4Header = (&mut pkt[0] as *mut u8) as *mut Ipv4Header;
        let tcp_hdr: *mut TcpHeader = (&mut pkt[0] as *mut u8).offset(20) as *mut TcpHeader;
        
        if let IpAddr::V4(ipv4) = flow.src_ip() {
            (*ip_hdr).set_src(ipv4);
        }
        if let IpAddr::V4(ipv4) = flow.dst_ip() {
            (*ip_hdr).set_dst(ipv4);
        }
        (*tcp_hdr).set_src_port(flow.src_port());
        (*tcp_hdr).set_dst_port(flow.dst_port());
        (*ip_hdr).set_protocol(ProtocolNumbers::Tcp);
    }
}
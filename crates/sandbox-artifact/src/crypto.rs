use crate::{error::io_error, ArtifactError, ArtifactScope};
use aes_gcm::{
    aead::{
        generic_array::GenericArray,
        rand_core::{OsRng, RngCore as _},
        stream::{DecryptorBE32, EncryptorBE32},
        Aead as _, KeyInit as _, Payload,
    },
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use runtrue_sandbox_core::ArtifactDescriptor;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"RTARTE01";
const FORMAT_VERSION: u32 = 1;
const CHUNK_BYTES: usize = 1024 * 1024;
const WRAP_NONCE_BYTES: usize = 12;
const STREAM_NONCE_BYTES: usize = 7;
const WRAPPED_KEY_BYTES: usize = 48;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: u64 = (MAGIC.len()
    + std::mem::size_of::<u32>() * 2
    + std::mem::size_of::<u64>()
    + WRAP_NONCE_BYTES
    + STREAM_NONCE_BYTES
    + WRAPPED_KEY_BYTES) as u64;

pub(crate) fn maximum_envelope_bytes(plaintext_bytes: u64) -> Result<u64, ArtifactError> {
    let chunks = plaintext_bytes
        .checked_add(CHUNK_BYTES as u64 - 1)
        .ok_or_else(|| ArtifactError::Invalid("encrypted object size overflow".to_owned()))?
        / CHUNK_BYTES as u64;
    plaintext_bytes
        .checked_add(chunks.saturating_mul(TAG_BYTES as u64))
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .ok_or_else(|| ArtifactError::Invalid("encrypted object size overflow".to_owned()))
}

pub(crate) struct EnvelopeKey(Zeroizing<[u8; 32]>);

impl EnvelopeKey {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn tenant_key(&self, scope: &ArtifactScope) -> Result<Zeroizing<[u8; 32]>, ArtifactError> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"runtrue-artifact-envelope-v1"), self.0.as_ref());
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(scope.binding().as_bytes(), key.as_mut())
            .map_err(|_| ArtifactError::Storage("derive tenant envelope key".to_owned()))?;
        Ok(key)
    }
}

pub(crate) fn describe(path: &Path, maximum: u64) -> Result<ArtifactDescriptor, ArtifactError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let mut digest = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| ArtifactError::Invalid("artifact size overflow".to_owned()))?;
        if size_bytes > maximum {
            return Err(ArtifactError::Invalid(
                "artifact exceeds the object byte limit".to_owned(),
            ));
        }
        digest.update(&buffer[..read]);
    }
    if size_bytes == 0 {
        return Err(ArtifactError::Invalid(
            "empty snapshot objects are not publishable".to_owned(),
        ));
    }
    Ok(ArtifactDescriptor {
        digest: format!("sha256:{}", hex::encode(digest.finalize())),
        size_bytes,
        media_type: String::new(),
    })
}

pub(crate) fn seal(
    source: &Path,
    destination: &Path,
    scope: &ArtifactScope,
    descriptor: &ArtifactDescriptor,
    key: &EnvelopeKey,
    deadline: Instant,
) -> Result<u64, ArtifactError> {
    check_deadline(deadline, "encrypt snapshot object")?;
    let mut plaintext = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| io_error(source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| io_error(destination, error))?;
    let tenant_key = key.tenant_key(scope)?;
    let mut data_key = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(data_key.as_mut());
    let mut wrap_nonce = [0_u8; WRAP_NONCE_BYTES];
    OsRng.fill_bytes(&mut wrap_nonce);
    let mut stream_nonce = [0_u8; STREAM_NONCE_BYTES];
    OsRng.fill_bytes(&mut stream_nonce);
    let aad = associated_data(scope, descriptor);
    let wrapping = Aes256Gcm::new_from_slice(tenant_key.as_ref())
        .map_err(|_| ArtifactError::Storage("initialize tenant envelope cipher".to_owned()))?;
    let wrapped = wrapping
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: data_key.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| ArtifactError::Storage("wrap artifact data key".to_owned()))?;
    if wrapped.len() != WRAPPED_KEY_BYTES {
        return Err(ArtifactError::Storage(
            "wrapped artifact key has an invalid size".to_owned(),
        ));
    }
    write_header(
        &mut output,
        descriptor.size_bytes,
        &wrap_nonce,
        &stream_nonce,
        &wrapped,
        destination,
    )?;
    let cipher = Aes256Gcm::new_from_slice(data_key.as_ref())
        .map_err(|_| ArtifactError::Storage("initialize artifact data cipher".to_owned()))?;
    let nonce = GenericArray::from_slice(&stream_nonce);
    let mut encryptor = EncryptorBE32::<Aes256Gcm>::from_aead(cipher, nonce);
    let mut remaining = descriptor.size_bytes;
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut observed_digest = Sha256::new();
    while remaining > CHUNK_BYTES as u64 {
        check_deadline(deadline, "encrypt snapshot object")?;
        let length = CHUNK_BYTES;
        plaintext
            .read_exact(&mut buffer[..length])
            .map_err(|error| io_error(source, error))?;
        observed_digest.update(&buffer[..length]);
        remaining -= length as u64;
        let ciphertext = encryptor
            .encrypt_next(Payload {
                msg: &buffer[..length],
                aad: &aad,
            })
            .map_err(|_| ArtifactError::Storage("encrypt artifact chunk".to_owned()))?;
        output
            .write_all(&ciphertext)
            .map_err(|error| io_error(destination, error))?;
    }
    let length = remaining as usize;
    plaintext
        .read_exact(&mut buffer[..length])
        .map_err(|error| io_error(source, error))?;
    observed_digest.update(&buffer[..length]);
    let ciphertext = encryptor
        .encrypt_last(Payload {
            msg: &buffer[..length],
            aad: &aad,
        })
        .map_err(|_| ArtifactError::Storage("encrypt final artifact chunk".to_owned()))?;
    output
        .write_all(&ciphertext)
        .map_err(|error| io_error(destination, error))?;
    let mut trailing = [0_u8; 1];
    if plaintext
        .read(&mut trailing)
        .map_err(|error| io_error(source, error))?
        != 0
        || format!("sha256:{}", hex::encode(observed_digest.finalize())) != descriptor.digest
    {
        return Err(ArtifactError::Integrity(
            "snapshot object changed while it was being encrypted".to_owned(),
        ));
    }
    output
        .sync_all()
        .map_err(|error| io_error(destination, error))?;
    let transferred = output
        .metadata()
        .map_err(|error| io_error(destination, error))?
        .len();
    data_key.zeroize();
    Ok(transferred)
}

pub(crate) fn open(
    source: &Path,
    destination: &Path,
    scope: &ArtifactScope,
    descriptor: &ArtifactDescriptor,
    key: &EnvelopeKey,
    deadline: Instant,
) -> Result<u64, ArtifactError> {
    check_deadline(deadline, "decrypt snapshot object")?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| io_error(source, error))?;
    let header = read_header(&mut input, source)?;
    if header.plaintext_bytes != descriptor.size_bytes {
        return Err(ArtifactError::Integrity(
            "encrypted object size does not match its descriptor".to_owned(),
        ));
    }
    let aad = associated_data(scope, descriptor);
    let tenant_key = key.tenant_key(scope)?;
    let wrapping = Aes256Gcm::new_from_slice(tenant_key.as_ref())
        .map_err(|_| ArtifactError::Storage("initialize tenant envelope cipher".to_owned()))?;
    let mut data_key = Zeroizing::new(
        wrapping
            .decrypt(
                Nonce::from_slice(&header.wrap_nonce),
                Payload {
                    msg: &header.wrapped_key,
                    aad: &aad,
                },
            )
            .map_err(|_| ArtifactError::Integrity("unwrap artifact data key".to_owned()))?,
    );
    if data_key.len() != 32 {
        return Err(ArtifactError::Integrity(
            "unwrapped artifact key has an invalid size".to_owned(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(&data_key)
        .map_err(|_| ArtifactError::Storage("initialize artifact data cipher".to_owned()))?;
    let nonce = GenericArray::from_slice(&header.stream_nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::from_aead(cipher, nonce);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| io_error(destination, error))?;
    let mut digest = Sha256::new();
    let mut remaining = descriptor.size_bytes;
    let mut ciphertext = vec![0_u8; CHUNK_BYTES + TAG_BYTES];
    while remaining > CHUNK_BYTES as u64 {
        check_deadline(deadline, "decrypt snapshot object")?;
        let plaintext_length = CHUNK_BYTES;
        let ciphertext_length = plaintext_length + TAG_BYTES;
        read_envelope_exact(&mut input, &mut ciphertext[..ciphertext_length], source)?;
        remaining -= plaintext_length as u64;
        let plaintext = decryptor
            .decrypt_next(Payload {
                msg: &ciphertext[..ciphertext_length],
                aad: &aad,
            })
            .map_err(|_| ArtifactError::Integrity("decrypt artifact chunk".to_owned()))?;
        digest.update(&plaintext);
        output
            .write_all(&plaintext)
            .map_err(|error| io_error(destination, error))?;
    }
    let plaintext_length = remaining as usize;
    let ciphertext_length = plaintext_length + TAG_BYTES;
    read_envelope_exact(&mut input, &mut ciphertext[..ciphertext_length], source)?;
    let plaintext = decryptor
        .decrypt_last(Payload {
            msg: &ciphertext[..ciphertext_length],
            aad: &aad,
        })
        .map_err(|_| ArtifactError::Integrity("decrypt final artifact chunk".to_owned()))?;
    digest.update(&plaintext);
    output
        .write_all(&plaintext)
        .map_err(|error| io_error(destination, error))?;
    let mut trailing = [0_u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|error| io_error(source, error))?
        != 0
    {
        return Err(ArtifactError::Integrity(
            "encrypted object contains trailing data".to_owned(),
        ));
    }
    let observed = format!("sha256:{}", hex::encode(digest.finalize()));
    if observed != descriptor.digest {
        return Err(ArtifactError::Integrity(
            "materialized object digest does not match its descriptor".to_owned(),
        ));
    }
    output
        .sync_all()
        .map_err(|error| io_error(destination, error))?;
    data_key.zeroize();
    Ok(input
        .metadata()
        .map_err(|error| io_error(source, error))?
        .len())
}

fn associated_data(scope: &ArtifactScope, descriptor: &ArtifactDescriptor) -> Vec<u8> {
    format!(
        "runtrue-artifact-v1\n{}\n{}\n{}\n{}",
        scope.binding(),
        descriptor.digest,
        descriptor.size_bytes,
        descriptor.media_type
    )
    .into_bytes()
}

fn write_header(
    output: &mut fs::File,
    plaintext_bytes: u64,
    wrap_nonce: &[u8; WRAP_NONCE_BYTES],
    stream_nonce: &[u8; STREAM_NONCE_BYTES],
    wrapped_key: &[u8],
    path: &Path,
) -> Result<(), ArtifactError> {
    output
        .write_all(MAGIC)
        .map_err(|error| io_error(path, error))?;
    output
        .write_all(&FORMAT_VERSION.to_be_bytes())
        .and_then(|()| output.write_all(&(CHUNK_BYTES as u32).to_be_bytes()))
        .and_then(|()| output.write_all(&plaintext_bytes.to_be_bytes()))
        .and_then(|()| output.write_all(wrap_nonce))
        .and_then(|()| output.write_all(stream_nonce))
        .and_then(|()| output.write_all(wrapped_key))
        .map_err(|error| io_error(path, error))
}

struct Header {
    plaintext_bytes: u64,
    wrap_nonce: [u8; WRAP_NONCE_BYTES],
    stream_nonce: [u8; STREAM_NONCE_BYTES],
    wrapped_key: [u8; WRAPPED_KEY_BYTES],
}

fn read_header(input: &mut fs::File, path: &Path) -> Result<Header, ArtifactError> {
    let mut magic = [0_u8; 8];
    let mut version = [0_u8; 4];
    let mut chunk_bytes = [0_u8; 4];
    let mut plaintext_bytes = [0_u8; 8];
    let mut wrap_nonce = [0_u8; WRAP_NONCE_BYTES];
    let mut stream_nonce = [0_u8; STREAM_NONCE_BYTES];
    let mut wrapped_key = [0_u8; WRAPPED_KEY_BYTES];
    let read = input
        .read_exact(&mut magic)
        .and_then(|()| input.read_exact(&mut version))
        .and_then(|()| input.read_exact(&mut chunk_bytes))
        .and_then(|()| input.read_exact(&mut plaintext_bytes))
        .and_then(|()| input.read_exact(&mut wrap_nonce))
        .and_then(|()| input.read_exact(&mut stream_nonce))
        .and_then(|()| input.read_exact(&mut wrapped_key));
    if let Err(error) = read {
        return Err(if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ArtifactError::Integrity("encrypted object is truncated".to_owned())
        } else {
            io_error(path, error)
        });
    }
    if &magic != MAGIC
        || u32::from_be_bytes(version) != FORMAT_VERSION
        || u32::from_be_bytes(chunk_bytes) != CHUNK_BYTES as u32
    {
        return Err(ArtifactError::Integrity(
            "encrypted object header is invalid".to_owned(),
        ));
    }
    Ok(Header {
        plaintext_bytes: u64::from_be_bytes(plaintext_bytes),
        wrap_nonce,
        stream_nonce,
        wrapped_key,
    })
}

fn read_envelope_exact(
    input: &mut fs::File,
    bytes: &mut [u8],
    path: &Path,
) -> Result<(), ArtifactError> {
    input.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ArtifactError::Integrity("encrypted object is truncated".to_owned())
        } else {
            io_error(path, error)
        }
    })
}

fn check_deadline(deadline: Instant, operation: &str) -> Result<(), ArtifactError> {
    if Instant::now() >= deadline {
        return Err(ArtifactError::Timeout(operation.to_owned()));
    }
    Ok(())
}

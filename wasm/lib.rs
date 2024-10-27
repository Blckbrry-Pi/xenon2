#![no_std]
#![feature(alloc_error_handler, const_mut_refs, allocator_api)]

extern crate alloc;

use argon2::{password_hash::Salt, Argon2, PasswordHash, PasswordVerifier};
use base64::Engine;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern "C" {
  fn panic(ptr: *const u8, len: usize);
}

#[panic_handler]
#[no_mangle]
pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
  let msg = alloc::format!("{info}");
  let ptr = msg.as_ptr();
  let len = msg.capacity();
  unsafe { panic(ptr, len) };

  loop {}
}

#[alloc_error_handler]
#[no_mangle]
pub fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
  panic!("Memory allocation of {} bytes failed", layout.size());
}

#[no_mangle]
pub unsafe fn alloc(size: usize) -> *mut u8 {
  let align = core::mem::align_of::<usize>();
  let layout = alloc::alloc::Layout::from_size_align_unchecked(size, align);
  alloc::alloc::alloc(layout)
}

#[no_mangle]
pub unsafe fn dealloc(ptr: *mut u8, size: usize) {
  let align = core::mem::align_of::<usize>();
  let layout = alloc::alloc::Layout::from_size_align_unchecked(size, align);
  alloc::alloc::dealloc(ptr, layout);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllParams {
  algorithm: argon2::Algorithm,
  version: argon2::Version,
  m_cost: u32,
  t_cost: u32,
  p_cost: u32,
}

static mut PARAMS: AllParams = AllParams {
  algorithm: argon2::Algorithm::Argon2id,
  version: argon2::Version::V0x13,
  m_cost: argon2::Params::DEFAULT_M_COST,
  t_cost: argon2::Params::DEFAULT_T_COST,
  p_cost: argon2::Params::DEFAULT_P_COST,
};

#[no_mangle]
pub unsafe fn setup_params(
  algorithm: [u8; 4],
  version: u32,
  m_cost: u32,
  t_cost: u32,
  p_cost: u32,
) {
  let algorithm = match &algorithm {
    b"i___" => argon2::Algorithm::Argon2i,
    b"d___" => argon2::Algorithm::Argon2d,
    b"id__" => argon2::Algorithm::Argon2id,
    _ => panic!("Invalid algorithm"),
  };

  let version = match version {
    0x10 => argon2::Version::V0x10,
    0x13 => argon2::Version::V0x13,
    _ => panic!("Invalid version"),
  };

  let params = argon2::ParamsBuilder::new()
    .m_cost(m_cost)
    .t_cost(t_cost)
    .p_cost(p_cost)
    .build()
    .expect("Invalid parameter memory, time, or paralellism");

    PARAMS = AllParams {
      algorithm,
      version,
      m_cost: params.m_cost(),
      t_cost: params.t_cost(),
      p_cost: params.p_cost(),
    };
}

#[no_mangle]
pub unsafe fn hash(
  password_ptr: *const u8,
  password_len: usize,

  salt_ptr: *const u8,
  salt_len: usize,

  secret_ptr: *const u8,
  secret_len: usize,

  output_ptr: *mut *mut u8,
) {
  let password = core::slice::from_raw_parts(password_ptr, password_len);
  let secret = if !secret_ptr.is_null() {
    Some(core::slice::from_raw_parts(secret_ptr, secret_len))
  } else {
    None
  };

  let salt = core::slice::from_raw_parts(salt_ptr, salt_len);
  let salt = base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt);
  let salt = Salt::from_b64(&salt).expect("Got invalid salt");

  let AllParams { algorithm, version, m_cost, t_cost, p_cost } = PARAMS;
  let params = argon2::Params::new(m_cost, t_cost, p_cost, None).unwrap();

  let hasher = if let Some(secret) = secret {
    Argon2::new_with_secret(secret, algorithm, version, params).unwrap()
  } else {
    Argon2::new(algorithm, version, params)
  };

  let hash = PasswordHash::generate(hasher, password, salt).expect("Failed to hash password");
  let digest = alloc::string::ToString::to_string(&hash);

  let mut digest = digest.into_bytes();
  digest.push(0);

  let digest_output = alloc(digest.len());
  for i in 0..digest.len() {
    *digest_output.add(i) = digest[i];
  }

  *output_ptr = digest_output;
}

#[no_mangle]
pub unsafe fn verify(
  digest_ptr: *const u8,
  digest_len: usize,

  password_ptr: *const u8,
  password_len: usize,
  
  secret_ptr: *const u8,
  secret_len: usize,

  matches: *mut u32,
) {
  let digest = core::slice::from_raw_parts(digest_ptr, digest_len);
  let digest = core::str::from_utf8(digest).expect("Invalid hash digest");

  let password = core::slice::from_raw_parts(password_ptr, password_len);
  let secret = if !secret_ptr.is_null() {
    Some(core::slice::from_raw_parts(secret_ptr, secret_len))
  } else {
    None
  };

  let hash = PasswordHash::new(digest).expect("Invalid digest format");
  let params = argon2::Params::try_from(&hash).expect("Invalid digest parameters");
  let algorithm = match hash.algorithm.as_str() {
    "argon2i" => argon2::Algorithm::Argon2i,
    "argon2d" => argon2::Algorithm::Argon2d,
    "argon2id" => argon2::Algorithm::Argon2id,
    _ => panic!("Invalid algorithm"),
  };
  let version = match hash.version {
    Some(0x10) => argon2::Version::V0x10,
    Some(0x13) => argon2::Version::V0x13,
    None => argon2::Version::default(),
    Some(_) => panic!("Invalid {algorithm} version"),
  };

  let hasher = if let Some(secret) = secret {
    Argon2::new_with_secret(secret, algorithm, version, params).unwrap()
  } else {
    Argon2::new(algorithm, version, params)
  };

  let password_valid = hasher.verify_password(password, &hash).is_ok();

  *matches = password_valid as u32;
}

//! DAVE persistence for the ad-hoc-signed macOS client. Discord's access group
//! cannot accompany that signature, so only DAVE items use the file-based keychain.

use phoenix_hook::image::Image;
use std::{ffi::c_void, ptr, sync::OnceLock};

type Ref = *const c_void;
type Status = i32;
type ItemFn = unsafe extern "C" fn(Ref, *mut Ref) -> Status;
type DeleteFn = unsafe extern "C" fn(Ref) -> Status;
type UpdateFn = unsafe extern "C" fn(Ref, Ref) -> Status;
type CreateFn = unsafe extern "C" fn(Ref, *mut Ref) -> Ref;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
   #[cfg(test)]
   static kCFTypeDictionaryKeyCallBacks: c_void;
   #[cfg(test)]
   static kCFTypeDictionaryValueCallBacks: c_void;
   fn CFRelease(value: Ref);
   fn CFGetTypeID(value: Ref) -> usize;
   fn CFDictionaryGetTypeID() -> usize;
   fn CFStringGetTypeID() -> usize;
   fn CFDataGetTypeID() -> usize;
   #[cfg(test)]
   fn CFDictionaryCreateMutable(a: Ref, n: isize, keys: Ref, values: Ref) -> Ref;
   fn CFDictionaryCreateMutableCopy(a: Ref, n: isize, source: Ref) -> Ref;
   fn CFDictionaryGetValue(dict: Ref, key: Ref) -> Ref;
   fn CFDictionarySetValue(dict: Ref, key: Ref, value: Ref);
   fn CFDictionaryRemoveValue(dict: Ref, key: Ref);
   fn CFStringCreateWithBytes(
      a: Ref,
      bytes: *const u8,
      len: isize,
      encoding: u32,
      external: bool,
   ) -> Ref;
   fn CFStringGetLength(value: Ref) -> isize;
   fn CFStringGetCString(value: Ref, buffer: *mut u8, size: isize, encoding: u32) -> bool;
   fn CFDataCreate(a: Ref, bytes: *const u8, len: isize) -> Ref;
   fn CFDataGetLength(data: Ref) -> isize;
   fn CFDataGetBytePtr(data: Ref) -> *const u8;
   fn CFNumberGetValue(number: Ref, kind: isize, out: *mut c_void) -> bool;
   fn CFErrorGetCode(error: Ref) -> isize;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
   static kSecAttrAccessGroup: Ref;
   static kSecAttrService: Ref;
   static kSecAttrApplicationTag: Ref;
   static kSecAttrLabel: Ref;
   static kSecPrivateKeyAttrs: Ref;
   static kSecAttrAccessible: Ref;
   static kSecUseDataProtectionKeychain: Ref;
   static kSecUseAuthenticationUI: Ref;
   static kSecUseAuthenticationUISkip: Ref;
   static kSecCodeInfoFlags: Ref;
   fn SecCodeCopySelf(flags: u32, out: *mut Ref) -> Status;
   fn SecCodeCopySigningInformation(code: Ref, flags: u32, out: *mut Ref) -> Status;
}

#[repr(C)]
struct ProcessSerialNumber {
   high: u32,
   low: u32,
}
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
   fn GetFrontProcess(out: *mut ProcessSerialNumber) -> Status;
   fn GetProcessPID(process: *const ProcessSerialNumber, out: *mut i32) -> Status;
}

struct Owned(Ref);
impl Drop for Owned {
   fn drop(&mut self) {
      // SAFETY: Owned holds one retained reference, or null on allocation failure.
      if !self.0.is_null() {
         unsafe { CFRelease(self.0) };
      }
   }
}
impl Owned {
   fn string(bytes: &[u8]) -> Self {
      // SAFETY: CF copies the borrowed bytes synchronously.
      Self(unsafe {
         CFStringCreateWithBytes(
            ptr::null(),
            bytes.as_ptr(),
            bytes.len().cast_signed(),
            0x0800_0100,
            false,
         )
      })
   }
   fn data(bytes: &[u8]) -> Self {
      // SAFETY: CF copies the borrowed bytes synchronously.
      Self(unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), bytes.len().cast_signed()) })
   }
   fn copy(dict: Ref) -> Self {
      // SAFETY: only called with a dictionary received from Security or CF.
      Self(unsafe { CFDictionaryCreateMutableCopy(ptr::null(), 0, dict) })
   }
}
fn get(dict: Ref, key: Ref) -> Ref {
   // SAFETY: dict is checked by dictionary(), or created by CF; key is a CF constant.
   unsafe { CFDictionaryGetValue(dict, key) }
}
fn dictionary(value: Ref) -> bool {
   // SAFETY: non-null values originate in a Security API's CF parameters.
   !value.is_null() && unsafe { CFGetTypeID(value) == CFDictionaryGetTypeID() }
}
fn text(value: Ref) -> Option<String> {
   // SAFETY: only CFString objects are passed to the string accessors. This
   // helper reads public service/group identifiers, never account identifiers.
   unsafe {
      if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
         return None;
      }
      let length = CFStringGetLength(value);
      if !(0..=256).contains(&length) {
         return None;
      }
      let mut bytes = vec![0; length.cast_unsigned() * 4 + 1];
      if !CFStringGetCString(
         value,
         bytes.as_mut_ptr(),
         bytes.len().cast_signed(),
         0x0800_0100,
      ) {
         return None;
      }
      let end = bytes.iter().position(|&b| b == 0)?;
      String::from_utf8(bytes[..end].to_vec()).ok()
   }
}
fn tag(value: Ref) -> Option<Owned> {
   const PREFIX: &[u8] = b"discord-secure-frames-key-";
   // SAFETY: after checking its type, CFData's bytes live for this borrowed call.
   unsafe {
      if value.is_null() || CFGetTypeID(value) != CFDataGetTypeID() {
         return None;
      }
      let length = usize::try_from(CFDataGetLength(value)).ok()?;
      if length <= PREFIX.len() {
         return None;
      }
      let bytes = std::slice::from_raw_parts(CFDataGetBytePtr(value), length);
      let suffix = bytes.strip_prefix(PREFIX)?;
      let mut renamed = b"sunbird-dave-key-".to_vec();
      renamed.extend_from_slice(suffix);
      Some(Owned::data(&renamed))
   }
}

/// Copies only positively identified DAVE queries; the caller's dictionaries
/// and every unrelated keychain operation retain their original behavior.
fn rewrite(input: Ref) -> Option<Owned> {
   if !dictionary(input) {
      return None;
   }
   // SAFETY: Security constants are valid CF keys. Nested attributes are checked
   // before being read. SetValue retains the replacement CF objects.
   unsafe {
      let group = text(get(input, kSecAttrAccessGroup))?;
      if !group.ends_with(".com.hnc.dave-persistent-keys") {
         return None;
      }
      let nested = get(input, kSecPrivateKeyAttrs);
      let attrs = if dictionary(nested) { nested } else { input };
      let renamed_tag = tag(get(attrs, kSecAttrApplicationTag));
      let generic =
         text(get(input, kSecAttrService)).as_deref() == Some("Discord Secure Frames Key");
      if renamed_tag.is_none() && !generic {
         return None;
      }
      let out = Owned::copy(input);
      if out.0.is_null() {
         return None;
      }
      for key in [
         kSecAttrAccessGroup,
         kSecUseDataProtectionKeychain,
         kSecAttrAccessible,
      ] {
         CFDictionaryRemoveValue(out.0, key);
      }
      if generic {
         let service = Owned::string(b"Sunbird DAVE Persistent Keys");
         if service.0.is_null() {
            return None;
         }
         CFDictionarySetValue(out.0, kSecAttrService, service.0);
      }
      if let Some(renamed) = renamed_tag {
         if renamed.0.is_null() {
            return None;
         }
         let copy = Owned::copy(attrs);
         if copy.0.is_null() {
            return None;
         }
         let label = Owned::string(b"Sunbird Voice Verification Key");
         if label.0.is_null() {
            return None;
         }
         for key in [
            kSecAttrAccessGroup,
            kSecUseDataProtectionKeychain,
            kSecAttrAccessible,
         ] {
            CFDictionaryRemoveValue(copy.0, key);
         }
         CFDictionarySetValue(copy.0, kSecAttrApplicationTag, renamed.0);
         CFDictionarySetValue(copy.0, kSecAttrLabel, label.0);
         if dictionary(nested) {
            CFDictionarySetValue(out.0, kSecPrivateKeyAttrs, copy.0);
         } else {
            CFDictionarySetValue(out.0, kSecAttrApplicationTag, renamed.0);
         }
      }
      CFDictionarySetValue(out.0, kSecUseAuthenticationUI, kSecUseAuthenticationUISkip);
      Some(out)
   }
}

fn foreground() -> bool {
   let mut process = ProcessSerialNumber { high: 0, low: 0 };
   let mut pid = 0;
   // SAFETY: both APIs initialize the supplied stack buffers synchronously.
   unsafe {
      GetFrontProcess(&raw mut process) == 0
         && GetProcessPID(&raw const process, &raw mut pid) == 0
         && pid == libc::getpid()
   }
}
fn ad_hoc() -> bool {
   let mut code = Owned(ptr::null());
   let mut info = Owned(ptr::null());
   let mut flags = 0_u32;
   // SAFETY: Security returns retained CF objects. kCFNumberSInt32Type is 3.
   unsafe {
      SecCodeCopySelf(0, &raw mut code.0) == 0
         && SecCodeCopySigningInformation(code.0, 0, &raw mut info.0) == 0
         && !get(info.0, kSecCodeInfoFlags).is_null()
         && CFNumberGetValue(get(info.0, kSecCodeInfoFlags), 3, (&raw mut flags).cast())
         && flags & 2 != 0
   }
}

struct Originals {
   add: ItemFn,
   find: ItemFn,
   delete: DeleteFn,
   update: UpdateFn,
   create: CreateFn,
}
static ORIGINALS: OnceLock<Originals> = OnceLock::new();

pub fn install(image: &Image<'static>) {
   if !ad_hoc() || ORIGINALS.get().is_some() {
      return;
   }
   let names = [
      c"SecItemAdd",
      c"SecItemCopyMatching",
      c"SecItemDelete",
      c"SecItemUpdate",
      c"SecKeyCreateRandomKey",
   ];
   let hooks = [
      add as *const () as usize,
      find as *const () as usize,
      delete as *const () as usize,
      update as *const () as usize,
      create as *const () as usize,
   ];
   let mut targets = Vec::new();
   let mut writes = Vec::new();
   for (name, hook) in names.into_iter().zip(hooks) {
      // SAFETY: these are system Security symbols with their declared C signatures.
      let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) } as usize;
      let slots = image.pointers_to(address);
      if address == 0 || slots.is_empty() {
         log::warn!("DAVE keychain: required Security import missing; leaving imports unchanged");
         return;
      }
      targets.push(address);
      writes.extend(slots.into_iter().map(|slot| (slot, hook)));
   }
   // SAFETY: each resolved symbol has the corresponding Security header signature.
   let originals = unsafe {
      Originals {
         add: std::mem::transmute::<usize, ItemFn>(targets[0]),
         find: std::mem::transmute::<usize, ItemFn>(targets[1]),
         delete: std::mem::transmute::<usize, DeleteFn>(targets[2]),
         update: std::mem::transmute::<usize, UpdateFn>(targets[3]),
         create: std::mem::transmute::<usize, CreateFn>(targets[4]),
      }
   };
   if ORIGINALS.set(originals).is_err() {
      return;
   }
   // SAFETY: only aligned slots pointing to the original Security APIs are changed,
   // before Phoenix starts. All wrappers forward unrelated requests unchanged.
   match unsafe { image.swap_words(&writes) } {
      Ok(_) => log::info!("DAVE keychain: installed scoped persistence compatibility"),
      Err(error) => log::warn!("DAVE keychain: imports not changed: {error}"),
   }
}

fn dispatch(query: Ref, mut call: impl FnMut(Ref) -> Status) -> Status {
   let copy = rewrite(query);
   let selected = copy.as_ref().map_or(query, |q| q.0);
   if copy.is_some() && foreground() {
      // A returned SecKey can carry this policy into its later private-key
      // export. Allow normal OS authorization before the lookup, not merely
      // after a failed lookup, so a new client signature can be approved.
      // SAFETY: selected is our mutable DAVE dictionary copy.
      unsafe { CFDictionaryRemoveValue(selected, kSecUseAuthenticationUI) };
   }
   call(selected)
}

unsafe extern "C" fn find(query: Ref, result: *mut Ref) -> Status {
   let original = ORIGINALS
      .get()
      .expect("imports installed after originals")
      .find;
   // SAFETY: preserves Security's signature, arguments and output ownership.
   dispatch(query, |q| unsafe { original(q, result) })
}
unsafe extern "C" fn add(query: Ref, result: *mut Ref) -> Status {
   let original = ORIGINALS
      .get()
      .expect("imports installed after originals")
      .add;
   // SAFETY: preserves Security's signature, arguments and output ownership.
   dispatch(query, |q| unsafe { original(q, result) })
}
unsafe extern "C" fn delete(query: Ref) -> Status {
   let original = ORIGINALS
      .get()
      .expect("imports installed after originals")
      .delete;
   // SAFETY: preserves Security's signature and borrowed query lifetime.
   dispatch(query, |q| unsafe { original(q) })
}
unsafe extern "C" fn update(query: Ref, attrs: Ref) -> Status {
   let original = ORIGINALS
      .get()
      .expect("imports installed after originals")
      .update;
   // SAFETY: only the query's storage namespace changes. The host's attributes
   // remain borrowed and Security validates them, preserving its error status.
   dispatch(query, |q| unsafe { original(q, attrs) })
}
unsafe extern "C" fn create(params: Ref, error: *mut Ref) -> Ref {
   let original = ORIGINALS
      .get()
      .expect("imports installed after originals")
      .create;
   let copy = rewrite(params);
   let selected = copy.as_ref().map_or(params, |q| q.0);
   // SAFETY: only a foreground, DAVE-specific creation can request normal OS UI;
   // key generation, error objects and key ownership remain Security's.
   unsafe {
      if copy.is_some() && foreground() {
         CFDictionaryRemoveValue(selected, kSecUseAuthenticationUI);
      }
      let key = original(selected, error);
      if copy.is_some() && key.is_null() && !error.is_null() && !(*error).is_null() {
         log::warn!(
            "DAVE keychain: key creation failed ({})",
            CFErrorGetCode(*error)
         );
      }
      key
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::ffi::CString;

   #[link(name = "CoreFoundation", kind = "framework")]
   unsafe extern "C" {
      static kCFBooleanTrue: Ref;
      fn CFEqual(a: Ref, b: Ref) -> bool;
      fn CFNumberCreate(a: Ref, kind: isize, value: *const c_void) -> Ref;
      fn CFArrayCreate(a: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
      static kCFTypeArrayCallBacks: c_void;
   }
   #[link(name = "Security", kind = "framework")]
   unsafe extern "C" {
      static kSecClass: Ref;
      static kSecClassKey: Ref;
      static kSecClassGenericPassword: Ref;
      static kSecAttrAccount: Ref;
      static kSecAttrKeyType: Ref;
      static kSecAttrKeyTypeECSECPrimeRandom: Ref;
      static kSecAttrKeySizeInBits: Ref;
      static kSecAttrIsPermanent: Ref;
      static kSecReturnRef: Ref;
      static kSecReturnData: Ref;
      static kSecValueData: Ref;
      static kSecUseKeychain: Ref;
      static kSecMatchSearchList: Ref;
      fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> Status;
      fn SecItemAdd(query: Ref, result: *mut Ref) -> Status;
      fn SecItemDelete(query: Ref) -> Status;
      fn SecKeyCreateRandomKey(params: Ref, error: *mut Ref) -> Ref;
      fn SecKeyCopyPublicKey(key: Ref) -> Ref;
      static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: Ref;
      fn SecKeyCreateSignature(key: Ref, algorithm: Ref, data: Ref, error: *mut Ref) -> Ref;
      fn SecKeyVerifySignature(
         key: Ref,
         algorithm: Ref,
         data: Ref,
         signature: Ref,
         error: *mut Ref,
      ) -> bool;
      fn SecKeychainOpen(path: *const i8, out: *mut Ref) -> Status;
      fn SecItemUpdate(query: Ref, attrs: Ref) -> Status;
      fn SecKeyCopyExternalRepresentation(key: Ref, error: *mut Ref) -> Ref;
      fn SecKeychainCreate(
         path: *const i8,
         len: u32,
         password: *const c_void,
         prompt: bool,
         access: Ref,
         out: *mut Ref,
      ) -> Status;
      fn SecKeychainDelete(keychain: Ref) -> Status;
   }
   fn empty() -> Owned {
      // SAFETY: standard retaining CF dictionary callbacks and default allocator.
      Owned(unsafe {
         CFDictionaryCreateMutable(
            ptr::null(),
            0,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
         )
      })
   }
   fn put(dict: Ref, key: Ref, value: Ref) {
      assert!(!dict.is_null() && !value.is_null());
      // SAFETY: all callers use test-owned mutable CF dictionaries and live values.
      unsafe { CFDictionarySetValue(dict, key, value) };
   }
   fn query(native: bool) -> Owned {
      let out = empty();
      let group = Owned::string(b"TESTTEAM.com.hnc.dave-persistent-keys");
      // SAFETY: all dictionary keys/values here are CF constants or test-owned objects.
      unsafe {
         put(out.0, kSecAttrAccessGroup, group.0);
         put(out.0, kSecUseDataProtectionKeychain, kCFBooleanTrue);
         if native {
            let tag = Owned::data(b"discord-secure-frames-key-disposable-test");
            put(out.0, kSecAttrApplicationTag, tag.0);
         } else {
            let service = Owned::string(b"Discord Secure Frames Key");
            let account = Owned::string(b"disposable-test");
            put(out.0, kSecAttrService, service.0);
            put(out.0, kSecAttrAccount, account.0);
         }
      }
      out
   }
   #[test]
   fn scopes_and_namespaces_without_mutating_originals() {
      for native in [false, true] {
         let input = query(native);
         let saved = Owned::copy(input.0);
         let out = rewrite(input.0).unwrap();
         // SAFETY: valid CF dictionaries. This examines synthetic identifiers only.
         unsafe {
            assert!(CFEqual(input.0, saved.0));
            assert!(get(out.0, kSecAttrAccessGroup).is_null());
            assert!(get(out.0, kSecUseDataProtectionKeychain).is_null());
            if native {
               let expected = Owned::data(b"sunbird-dave-key-disposable-test");
               assert!(CFEqual(get(out.0, kSecAttrApplicationTag), expected.0));
            } else {
               assert_eq!(
                  text(get(out.0, kSecAttrService)).unwrap(),
                  "Sunbird DAVE Persistent Keys"
               );
               assert!(CFEqual(
                  get(out.0, kSecAttrAccount),
                  get(input.0, kSecAttrAccount)
               ));
            }
         }
      }
      let input = query(false);
      // SAFETY: mutation is confined to the synthetic test dictionary.
      unsafe { CFDictionaryRemoveValue(input.0, kSecAttrAccessGroup) };
      assert!(rewrite(input.0).is_none());
      let bad_group = Owned::string(b"TESTTEAM.com.hnc.agekeys");
      unsafe { put(input.0, kSecAttrAccessGroup, bad_group.0) };
      assert!(rewrite(input.0).is_none());
   }
   #[test]
   fn nested_creation_keeps_permanence_and_the_original_tag() {
      let attrs = query(true);
      let params = query(false);
      // SAFETY: all values are synthetic CF dictionaries/constant attributes.
      unsafe {
         put(attrs.0, kSecAttrIsPermanent, kCFBooleanTrue);
         put(params.0, kSecPrivateKeyAttrs, attrs.0);
         let saved = Owned::copy(attrs.0);
         let rewritten = rewrite(params.0).unwrap();
         let inner = get(rewritten.0, kSecPrivateKeyAttrs);
         assert!(CFEqual(saved.0, attrs.0));
         assert_eq!(get(inner, kSecAttrIsPermanent), kCFBooleanTrue);
         assert_eq!(
            text(get(inner, kSecAttrLabel)).unwrap(),
            "Sunbird Voice Verification Key"
         );
      }
   }
   #[test]
   fn forwards_unrelated_calls_and_preserves_denial_and_cancellation() {
      let unrelated = empty();
      let mut calls = 0;
      assert_eq!(
         dispatch(unrelated.0, |q| {
            calls += 1;
            assert_eq!(q, unrelated.0);
            -50
         }),
         -50
      );
      assert_eq!(calls, 1);
      for status in [-128, -25293] {
         let input = query(false);
         let mut calls = 0;
         assert_eq!(
            dispatch(input.0, |_| {
               calls += 1;
               status
            }),
            status
         );
         assert_eq!(calls, 1);
      }
   }

   struct Cleanup(Ref, std::path::PathBuf);
   impl Drop for Cleanup {
      fn drop(&mut self) {
         // SAFETY: this is solely the disposable keychain created above.
         unsafe { SecKeychainDelete(self.0) };
         let _ = std::fs::remove_dir_all(&self.1);
      }
   }

   /// Kept explicit: writes disposable keys only into a temporary encrypted
   /// keychain, never changes the user's default keychain or its search list.
   #[test]
   #[expect(
      clippy::too_many_lines,
      reason = "one disposable-keychain lifecycle covers native and generic operations"
   )]
   #[ignore = "requires local macOS keychain services; uses only disposable fixture keys"]
   fn disposable_keychain_round_trip() {
      let directory = std::env::temp_dir().join(format!(
         "sunbird-dave-{}-{:?}",
         std::process::id(),
         std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
      ));
      std::fs::create_dir(&directory).unwrap();
      let file = CString::new(
         directory
            .join("test.keychain")
            .as_os_str()
            .as_encoded_bytes(),
      )
      .unwrap();
      let password = b"disposable-fixture-not-a-user-secret";
      let mut keychain = Owned(ptr::null());
      // SAFETY: the test uses a new private path, explicit password and output slot.
      let status = unsafe {
         SecKeychainCreate(
            file.as_ptr(),
            u32::try_from(password.len()).unwrap(),
            password.as_ptr().cast(),
            false,
            ptr::null(),
            &raw mut keychain.0,
         )
      };
      assert_eq!(status, 0);
      let _cleanup = Cleanup(keychain.0, directory);
      let search = unsafe {
         Owned(CFArrayCreate(
            ptr::null(),
            &raw const keychain.0,
            1,
            &raw const kCFTypeArrayCallBacks,
         ))
      };
      let original = query(true);
      let params = empty();
      let bits = 256_i32;
      let size = unsafe { Owned(CFNumberCreate(ptr::null(), 3, (&raw const bits).cast())) };
      unsafe {
         let group = get(original.0, kSecAttrAccessGroup);
         put(original.0, kSecAttrIsPermanent, kCFBooleanTrue);
         put(params.0, kSecAttrAccessGroup, group);
         put(params.0, kSecUseDataProtectionKeychain, kCFBooleanTrue);
         put(params.0, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
         put(params.0, kSecAttrKeySizeInBits, size.0);
         put(params.0, kSecPrivateKeyAttrs, original.0);
         put(params.0, kSecUseKeychain, keychain.0);
      }
      let rewritten = rewrite(params.0).unwrap();
      let mut error = Owned(ptr::null());
      let key = unsafe { Owned(SecKeyCreateRandomKey(rewritten.0, &raw mut error.0)) };
      assert!(
         !key.0.is_null(),
         "native key creation error {}",
         if error.0.is_null() {
            0
         } else {
            unsafe { CFErrorGetCode(error.0) }
         }
      );
      let query = rewrite(original.0).unwrap();
      unsafe {
         CFDictionaryRemoveValue(query.0, kSecAttrIsPermanent);
         put(query.0, kSecClass, kSecClassKey);
         put(query.0, kSecReturnRef, kCFBooleanTrue);
         put(query.0, kSecMatchSearchList, search.0);
      }
      let mut loaded = Owned(ptr::null());
      assert_eq!(
         unsafe { SecItemCopyMatching(query.0, &raw mut loaded.0) },
         0
      );
      let public_a = unsafe { Owned(SecKeyCopyPublicKey(key.0)) };
      let public_b = unsafe { Owned(SecKeyCopyPublicKey(loaded.0)) };
      let message = Owned::data(b"disposable signing fixture");
      let signature = unsafe {
         Owned(SecKeyCreateSignature(
            loaded.0,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            message.0,
            &raw mut error.0,
         ))
      };
      assert!(!signature.0.is_null());
      assert!(unsafe {
         SecKeyVerifySignature(
            public_a.0,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            message.0,
            signature.0,
            &raw mut error.0,
         )
      });
      let bytes_a = unsafe {
         Owned(SecKeyCopyExternalRepresentation(
            public_a.0,
            &raw mut error.0,
         ))
      };
      let bytes_b = unsafe {
         Owned(SecKeyCopyExternalRepresentation(
            public_b.0,
            &raw mut error.0,
         ))
      };
      assert!(unsafe { CFEqual(bytes_a.0, bytes_b.0) });
      // Reload the same key in a fresh process; only the public bytes are passed
      // in memory to the child for an equality check.
      let expected = unsafe {
         std::slice::from_raw_parts(
            CFDataGetBytePtr(bytes_a.0),
            CFDataGetLength(bytes_a.0).cast_unsigned(),
         )
      };
      let mut expected_hex = String::new();
      for byte in expected {
         use std::fmt::Write;
         write!(expected_hex, "{byte:02x}").unwrap();
      }
      let child = std::process::Command::new(std::env::current_exe().unwrap())
         .args([
            "--exact",
            "dave_keychain::tests::reload_disposable_key",
            "--ignored",
         ])
         .env("SUNBIRD_DAVE_FIXTURE_KEYCHAIN", file.to_str().unwrap())
         .env("SUNBIRD_DAVE_FIXTURE_PUBLIC", &expected_hex)
         .output()
         .unwrap();
      assert!(
         child.status.success(),
         "fresh-process fixture failed: {}",
         String::from_utf8_lossy(&child.stdout)
      );

      unsafe { CFDictionaryRemoveValue(query.0, kSecReturnRef) };
      assert_eq!(unsafe { SecItemDelete(query.0) }, 0);
      assert_eq!(
         unsafe { SecItemCopyMatching(query.0, ptr::null_mut()) },
         -25300
      );
      let generic = rewrite(super::tests::query(false).0).unwrap();
      let data = Owned::data(b"disposable fixture bytes");
      unsafe {
         put(generic.0, kSecClass, kSecClassGenericPassword);
         put(generic.0, kSecValueData, data.0);
         put(generic.0, kSecUseKeychain, keychain.0);
      }
      assert_eq!(unsafe { SecItemAdd(generic.0, ptr::null_mut()) }, 0);
      unsafe {
         CFDictionaryRemoveValue(generic.0, kSecValueData);
         CFDictionaryRemoveValue(generic.0, kSecUseKeychain);
         put(generic.0, kSecMatchSearchList, search.0);
         put(generic.0, kSecReturnData, kCFBooleanTrue);
      }
      let mut found = Owned(ptr::null());
      assert_eq!(
         unsafe { SecItemCopyMatching(generic.0, &raw mut found.0) },
         0
      );
      assert!(unsafe { CFEqual(found.0, data.0) });
      let updates = empty();
      let replacement = Owned::data(b"replacement fixture bytes");
      unsafe {
         CFDictionaryRemoveValue(generic.0, kSecReturnData);
         put(updates.0, kSecValueData, replacement.0);
      }
      assert_eq!(unsafe { SecItemUpdate(generic.0, updates.0) }, 0);
      unsafe { put(generic.0, kSecReturnData, kCFBooleanTrue) };
      let mut reloaded = Owned(ptr::null());
      assert_eq!(
         unsafe { SecItemCopyMatching(generic.0, &raw mut reloaded.0) },
         0
      );
      assert!(unsafe { CFEqual(reloaded.0, replacement.0) });
      unsafe { CFDictionaryRemoveValue(generic.0, kSecReturnData) };
      assert_eq!(unsafe { SecItemDelete(generic.0) }, 0);
   }
   #[test]
   #[ignore = "child entry point for disposable_keychain_round_trip"]
   fn reload_disposable_key() {
      let Ok(path) = std::env::var("SUNBIRD_DAVE_FIXTURE_KEYCHAIN") else {
         return;
      };
      let expected = std::env::var("SUNBIRD_DAVE_FIXTURE_PUBLIC").unwrap();
      let path = CString::new(path).unwrap();
      let mut keychain = Owned(ptr::null());
      // SAFETY: opens only the parent's explicitly named disposable keychain.
      assert_eq!(
         unsafe { SecKeychainOpen(path.as_ptr(), &raw mut keychain.0) },
         0
      );
      let search = unsafe {
         Owned(CFArrayCreate(
            ptr::null(),
            &raw const keychain.0,
            1,
            &raw const kCFTypeArrayCallBacks,
         ))
      };
      let query = rewrite(query(true).0).unwrap();
      unsafe {
         put(query.0, kSecClass, kSecClassKey);
         put(query.0, kSecReturnRef, kCFBooleanTrue);
         put(query.0, kSecMatchSearchList, search.0);
      }
      let mut key = Owned(ptr::null());
      assert_eq!(unsafe { SecItemCopyMatching(query.0, &raw mut key.0) }, 0);
      let public = unsafe { Owned(SecKeyCopyPublicKey(key.0)) };
      let mut error = Owned(ptr::null());
      let bytes = unsafe { Owned(SecKeyCopyExternalRepresentation(public.0, &raw mut error.0)) };
      assert!(!bytes.0.is_null());
      let bytes = unsafe {
         std::slice::from_raw_parts(
            CFDataGetBytePtr(bytes.0),
            CFDataGetLength(bytes.0).cast_unsigned(),
         )
      };
      let mut hex = String::new();
      for byte in bytes {
         use std::fmt::Write;
         write!(hex, "{byte:02x}").unwrap();
      }
      assert!(hex == expected, "reloaded public key changed");
   }
}

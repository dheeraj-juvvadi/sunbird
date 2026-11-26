use super::*;
use phoenix_hook::image::{FunctionStarts, Segment};
use std::borrow::Cow;

fn fixture(offsets: &[u32], release: bool) -> Image<'static> {
   let mut code = vec![0; 0x100];
   let mut put = |at: usize, words: &[u32]| {
      for (index, word) in words.iter().enumerate() {
         code[at + index * 4..at + index * 4 + 4].copy_from_slice(&word.to_le_bytes());
      }
   };
   put(
      0x10,
      &[
         0xF940_083A, // ldr x26, [x1, #16]
         0x9102_03E8, // add x8, sp, #128
         0x9100_83E1, // add x1, sp, #32
         0x9100_43E2, // add x2, sp, #16
         0xAA16_03E0, // mov x0, x22
         0xD63F_0340, // blr x26
      ],
   );
   let mut starts = vec![0x10, 0x40];
   for (index, offset) in offsets.iter().enumerate() {
      let at = 0x50 + index * 0x40;
      let displacement = (0x10_i32 - i32::try_from(at + 12).unwrap()) / 4;
      put(
         at,
         &[
            0x9100_0260 | (offset << 10), // add x0, x19, #offset
            0x9100_03E1,                  // mov x1, sp
            0xAA14_03E8,                  // mov x8, x20
            0x9400_0000 | (displacement.cast_unsigned() & 0x03FF_FFFF),
            0x5280_0188,
            if release { 0xF868_0268 } else { 0xD503_201F },
         ],
      );
      starts.push(0x40);
   }
   starts.push(0);
   Image {
      path: String::new(),
      build_id: None,
      segments: vec![
         Segment {
            addr: 0x1000,
            bytes: Cow::Owned(code),
            executable: true,
            writable: false,
         },
         Segment {
            addr: 0x2000,
            bytes: Cow::Owned(starts.clone()),
            executable: false,
            writable: false,
         },
      ],
      eh_frame_hdr: None,
      arm_exidx: None,
      pdata: None,
      pointer_width: 8,
      function_starts: Some(FunctionStarts::new(0x2000, starts.len(), 0x1000)),
   }
}

#[test]
fn derives_store_offset_from_the_borrowing_dispatch_wrapper() {
   assert_eq!(gateway_store_offset(&fixture(&[16], true)).unwrap(), 16);
   assert_eq!(gateway_store_offset(&fixture(&[32], true)).unwrap(), 32);
   assert_eq!(gateway_store_offset(&fixture(&[16, 16], true)).unwrap(), 16);
}

#[test]
fn rejects_conflicting_or_unvalidated_store_offsets() {
   assert!(gateway_store_offset(&fixture(&[16, 32], true)).is_err());
   assert!(gateway_store_offset(&fixture(&[16], false)).is_err());
}

#[test]
fn rejects_clobbered_store_addresses() {
   for (at, word) in [
      (0x54, 0xAA16_03E0_u32), // mov x0, x22 overwrites the store argument
      (0x58, 0xAA16_03F3_u32), // mov x19, x22 overwrites the cell pointer
      (0x54, 0x9400_0000_u32), // a call can clobber argument registers
   ] {
      let mut image = fixture(&[16], true);
      image.segments[0].bytes.to_mut()[at..at + 4].copy_from_slice(&word.to_le_bytes());
      assert!(gateway_store_offset(&image).is_err());
   }
}

#[test]
fn requires_the_gateway_handler_field() {
   let mut image = fixture(&[16], true);
   // ldr x26, [x1, #24] does not load the handler field.
   image.segments[0].bytes.to_mut()[0x10..0x14].copy_from_slice(&0xF940_0C3A_u32.to_le_bytes());
   assert!(gateway_store_offset(&image).is_err());
}

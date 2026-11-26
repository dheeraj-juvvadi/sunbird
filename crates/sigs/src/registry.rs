use std::collections::HashMap;

use phoenix_hook::image::Image;

use crate::GATEWAY_HANDLER_FIELD;

/// Every Phoenix build has this event, so its entry seeds the walk.
const SEED: &str = "MESSAGE_CREATE";
/// Seeds the walk over the session/domain reducers (`READY_SUPPLEMENTAL`,
/// `RESUMED`, etc.) whose slice sits separately from the main registry or
/// domain table.
const DOMAIN_SEED: &str = "READY_SUPPLEMENTAL";
/// Seeds a separate flat table when the primary and domain walks miss this event.
const SPLIT_SEED: &str = "MESSAGE_UPDATE";
const STRIDE: usize = 3 * size_of::<usize>();
/// Stride of a `libdiscord` domain reducer descriptor:
/// `{domain_name_ptr, domain_name_len, domain_id, slice_ptr, slice_len}`.
const DOMAIN_STRIDE: usize = 5 * size_of::<usize>();
const MAX_NAME: usize = 64;

#[derive(Debug, flub::Error)]
pub enum Error {
   #[error("no gateway table holds {seed}")]
   NotFound { seed: &'static str },
   #[error("{} gateway tables hold {seed}", .slots.len())]
   Ambiguous {
      seed:  &'static str,
      slots: Vec<usize>,
   },
   #[error("gateway tables disagree on {event}: {expected:#x} and {found:#x}")]
   ConflictingHandler {
      event:    String,
      expected: usize,
      found:    usize,
   },
}

/// A gateway event that exists in the loaded target. Only
/// [`GatewayRegistry`] makes these, so holding one proves the event is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId(usize);

impl EventId {
   /// Position in [`GatewayRegistry::iter`] order.
   #[must_use]
   pub const fn index(self) -> usize {
      self.0
   }
}

#[derive(Clone, Debug)]
pub struct GatewayEntry {
   pub name:    String,
   /// All registry table slots holding this event's `{name_ptr, name_len,
   /// handler}` record. The compiler can emit duplicate copies of the static
   /// domain table across codegen units.
   pub slots:   Vec<usize>,
   pub handler: usize,
}

/// The target's gateway registry, walked from [`SEED`].
///
/// The walk crosses either a flat `{name_ptr, name_len, handler}` table
/// or `libdiscord`'s per-domain descriptor table,
/// plus any separate [`DOMAIN_SEED`] slice (`READY_SUPPLEMENTAL`, etc.).
pub struct GatewayRegistry {
   entries: Vec<GatewayEntry>,
   by_name: HashMap<String, EventId>,
}

impl GatewayRegistry {
   pub fn locate(image: &Image<'_>) -> Result<Self, Error> {
      let mut entries = locate_primary(image)?;
      match walk_flat(image, DOMAIN_SEED) {
         Ok(domain) => merge_entries(&mut entries, domain)?,
         Err(Error::NotFound { .. }) => {},
         Err(err) => return Err(err),
      }

      if !entries.iter().any(|entry| entry.name == SPLIT_SEED) {
         match walk_flat(image, SPLIT_SEED) {
            Ok(split) => merge_entries(&mut entries, split)?,
            Err(Error::NotFound { .. }) => {},
            Err(err) => return Err(err),
         }
      }

      let by_name = entries
         .iter()
         .enumerate()
         .map(|(index, entry)| (entry.name.clone(), EventId(index)))
         .collect();

      Ok(Self { entries, by_name })
   }

   #[must_use]
   pub fn id(&self, name: &str) -> Option<EventId> {
      self.by_name.get(name).copied()
   }

   /// # Panics
   ///
   /// When `id` came from another registry, which one process never has.
   #[must_use]
   pub fn entry(&self, id: EventId) -> &GatewayEntry {
      &self.entries[id.0]
   }

   pub fn iter(&self) -> impl Iterator<Item = (EventId, &GatewayEntry)> {
      self
         .entries
         .iter()
         .enumerate()
         .map(|(index, entry)| (EventId(index), entry))
   }
}

/// Finds the primary event table(s) containing [`SEED`]. Supports both a
/// single flat table and one or more per-domain descriptor tables.
fn locate_primary(image: &Image<'_>) -> Result<Vec<GatewayEntry>, Error> {
   let mut seeds = table_entries(image, SEED, GATEWAY_HANDLER_FIELD);
   seeds.sort_unstable();
   seeds.dedup();
   if seeds.is_empty() {
      return Err(Error::NotFound { seed: SEED });
   }

   // Try walking domain descriptor tables anchored at each seed slice first.
   let mut domain_entries = Vec::new();
   for &(slot, _) in &seeds {
      let slice_start = walk_slice_start(image, slot);
      let Some(found) = walk_domains_from_slice(image, slice_start)? else {
         continue;
      };
      merge_entries(&mut domain_entries, found)?;
   }
   if !domain_entries.is_empty() {
      return Ok(domain_entries);
   }

   flat_entries(image, SEED, &seeds)
}

fn merge_entries(target: &mut Vec<GatewayEntry>, incoming: Vec<GatewayEntry>) -> Result<(), Error> {
   for entry in incoming {
      if let Some(existing) = target.iter_mut().find(|known| known.name == entry.name) {
         if existing.handler != entry.handler {
            return Err(Error::ConflictingHandler {
               event:    entry.name,
               expected: existing.handler,
               found:    entry.handler,
            });
         }
         for slot in entry.slots {
            if !existing.slots.contains(&slot) {
               existing.slots.push(slot);
            }
         }
      } else {
         target.push(entry);
      }
   }
   Ok(())
}

fn entry(image: &Image<'_>, slot: usize) -> Option<GatewayEntry> {
   let ptr_size = image.pointer_width;
   let name = image.read_usize(slot)?;
   let len = image.read_usize(slot + ptr_size)?;
   let handler = image.read_usize(slot + 2 * ptr_size)?;
   if !(1..=MAX_NAME).contains(&len) || !image.is_function(handler) {
      return None;
   }
   let name = image.read(name, len)?;
   if !name
      .iter()
      .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
   {
      return None;
   }
   Some(GatewayEntry {
      name: String::from_utf8(name.to_vec()).ok()?,
      slots: vec![slot],
      handler,
   })
}

fn walk_slice_start(image: &Image<'_>, start: usize) -> usize {
   let stride = 3 * image.pointer_width;
   let mut first = start;
   while let Some(previous) = first.checked_sub(stride)
      && entry(image, previous).is_some()
   {
      first = previous;
   }
   first
}

fn walk_from_slot(image: &Image<'_>, start: usize) -> Vec<GatewayEntry> {
   let stride = 3 * image.pointer_width;
   let first = walk_slice_start(image, start);
   (0..)
      .map(|index| first + index * stride)
      .map_while(|slot| entry(image, slot))
      .collect()
}

fn walk_flat(image: &Image<'_>, seed: &'static str) -> Result<Vec<GatewayEntry>, Error> {
   let mut seeds = table_entries(image, seed, 2 * image.pointer_width);
   seeds.sort_unstable();
   seeds.dedup();
   flat_entries(image, seed, &seeds)
}

fn flat_entries(
   image: &Image<'_>,
   seed: &'static str,
   seeds: &[(usize, usize)],
) -> Result<Vec<GatewayEntry>, Error> {
   let mut entries = Vec::new();
   for &(slot, _) in seeds {
      let found = walk_from_slot(image, slot);
      // A string slice immediately before a vtable can look like one entry.
      // Accept isolated entries only when there is no competing candidate.
      if found.len() > 1 || seeds.len() == 1 {
         merge_entries(&mut entries, found)?;
      }
   }
   if entries.is_empty() {
      return Err(if seeds.is_empty() {
         Error::NotFound { seed }
      } else {
         Error::Ambiguous {
            seed,
            slots: seeds.iter().map(|&(slot, _)| slot).collect(),
         }
      });
   }
   Ok(entries)
}

/// Checks whether `slice_start` is referenced by a 5-word `libdiscord` domain
/// descriptor `{name_ptr, name_len, domain_id, slice_ptr, slice_len}` and, if
/// so, walks the entire contiguous domain table.
fn walk_domains_from_slice(
   image: &Image<'_>,
   slice_start: usize,
) -> Result<Option<Vec<GatewayEntry>>, Error> {
   let ptr_size = image.pointer_width;
   let domain_stride = 5 * ptr_size;
   let slice_field = 3 * ptr_size;

   let Some(anchor) = image
      .pointers_to(slice_start)
      .into_iter()
      .filter_map(|ptr_slot| ptr_slot.checked_sub(slice_field))
      .find(|&desc| domain_entries(image, desc).is_some())
   else {
      return Ok(None);
   };

   let mut first = anchor;
   while let Some(prev) = first.checked_sub(domain_stride)
      && domain_entries(image, prev).is_some()
   {
      first = prev;
   }

   let mut out = Vec::new();
   let mut domains = 0usize;
   let mut cur = first;
   while let Some(slice_entries) = domain_entries(image, cur) {
      domains += 1;
      merge_entries(&mut out, slice_entries)?;
      cur += domain_stride;
   }
   Ok((domains >= 2 && !out.is_empty()).then_some(out))
}

/// Parses one `libdiscord` domain descriptor at `addr`:
/// `{name_ptr, name_len, domain_id, slice_ptr, slice_len}`.
fn domain_entries(image: &Image<'_>, addr: usize) -> Option<Vec<GatewayEntry>> {
   let ptr_size = image.pointer_width;
   let name_ptr = image.read_usize(addr)?;
   let name_len = image.read_usize(addr + ptr_size)?;
   let domain_id = image.read_usize(addr + 2 * ptr_size)?;
   let slice_ptr = image.read_usize(addr + 3 * ptr_size)?;
   let slice_len = image.read_usize(addr + 4 * ptr_size)?;

   if !(1..=MAX_NAME).contains(&name_len) || domain_id > 1024 || slice_len > 256 {
      return None;
   }
   let name = image.read(name_ptr, name_len)?;
   if !name
      .iter()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
   {
      return None;
   }
   let stride = 3 * ptr_size;
   let mut out = Vec::with_capacity(slice_len);
   for index in 0..slice_len {
      out.push(entry(image, slice_ptr + index * stride)?);
   }
   Some(out)
}

/// `(slot, code)` for every `{name ptr, name len, ...}` entry named `key` whose
/// pointer `field` bytes in starts a function.
fn table_entries(image: &Image<'_>, key: &str, field: usize) -> Vec<(usize, usize)> {
   let ptr_size = image.pointer_width;
   let field = if field == GATEWAY_HANDLER_FIELD {
      2 * ptr_size
   } else {
      field
   };
   let mut out = Vec::new();
   for string in image.find_bytes_iter(key.as_bytes()) {
      for slot in image.pointers_to(string) {
         if image.read_usize(slot + ptr_size) != Some(key.len()) {
            continue;
         }
         let Some(code) = image.read_usize(slot + field) else {
            continue;
         };
         if image.is_function(code) {
            out.push((slot, code));
         }
      }
   }
   // Keep compile-time constants referenced on 64-bit targets.
   let _ = (STRIDE, DOMAIN_STRIDE);
   out
}

#[cfg(test)]
mod tests {
   use super::*;
   use phoenix_hook::image::Segment;
   use std::borrow::Cow;

   fn image() -> Image<'static> {
      Image {
         path: "registry fixture".to_owned(),
         build_id: None,
         segments: vec![
            Segment {
               addr: 0x1000,
               bytes: Cow::Owned(vec![0; 0x1000]),
               executable: false,
               writable: false,
            },
            Segment {
               addr: 0x3000,
               bytes: Cow::Owned(vec![0; 0x100]),
               executable: true,
               writable: false,
            },
         ],
         eh_frame_hdr: None,
         arm_exidx: None,
         pdata: None,
         pointer_width: 8,
         function_starts: None,
      }
   }

   fn words(image: &mut Image<'_>, addr: usize, words: &[usize]) {
      for (index, word) in words.iter().enumerate() {
         let width = image.pointer_width;
         let offset = addr - 0x1000 + index * width;
         image.segments[0].bytes.to_mut()[offset..offset + width]
            .copy_from_slice(&word.to_le_bytes()[..width]);
      }
   }

   fn name(image: &mut Image<'_>, addr: usize, text: &str) {
      let offset = addr - 0x1000;
      image.segments[0].bytes.to_mut()[offset..offset + text.len()]
         .copy_from_slice(text.as_bytes());
   }

   fn table(image: &mut Image<'_>, addr: usize, handler: usize) {
      words(
         image,
         addr,
         &[
            0x1000,
            SEED.len(),
            handler,
            0x1040,
            SPLIT_SEED.len(),
            0x3010,
         ],
      );
   }

   #[test]
   fn ignores_isolated_lookalike_before_duplicate_flat_tables() {
      let mut image = image();
      name(&mut image, 0x1000, SEED);
      name(&mut image, 0x1020, SEED);
      name(&mut image, 0x1040, SPLIT_SEED);
      words(
         &mut image,
         0x1100,
         &[0x1000, SEED.len(), 0x3020, 8, 8, 0x3030],
      );
      table(&mut image, 0x1200, 0x3000);
      // A second string allocation must also be searched.
      words(&mut image, 0x1200, &[0x1020]);
      table(&mut image, 0x1300, 0x3000);
      let registry = GatewayRegistry::locate(&image).unwrap();
      let entry = registry.entry(registry.id(SEED).unwrap());
      assert_eq!(entry.handler, 0x3000);
      assert_eq!(entry.slots, [0x1200, 0x1300]);
      assert_eq!(registry.iter().count(), 2);
   }

   #[test]
   fn conflicting_valid_tables_are_an_error() {
      let mut image = image();
      name(&mut image, 0x1000, SEED);
      name(&mut image, 0x1040, SPLIT_SEED);
      table(&mut image, 0x1200, 0x3000);
      table(&mut image, 0x1300, 0x3020);
      assert!(matches!(
         GatewayRegistry::locate(&image),
         Err(Error::ConflictingHandler { .. })
      ));
   }

   #[test]
   fn preserves_single_entry_registry() {
      let mut image = image();
      name(&mut image, 0x1000, SEED);
      words(&mut image, 0x1100, &[0x1000, SEED.len(), 0x3000]);
      let registry = GatewayRegistry::locate(&image).unwrap();
      assert_eq!(registry.iter().count(), 1);
   }

   #[test]
   fn domain_descriptors_take_precedence_over_isolated_lookalike() {
      let mut image = image();
      name(&mut image, 0x1000, SEED);
      name(&mut image, 0x1040, SPLIT_SEED);
      name(&mut image, 0x1080, "messages");
      name(&mut image, 0x1090, "updates");
      words(&mut image, 0x1100, &[0x1000, SEED.len(), 0x3020]);
      words(&mut image, 0x1200, &[0x1000, SEED.len(), 0x3000]);
      words(&mut image, 0x1300, &[0x1040, SPLIT_SEED.len(), 0x3010]);
      words(
         &mut image,
         0x1400,
         &[0x1080, 8, 0, 0x1200, 1, 0x1090, 7, 1, 0x1300, 1],
      );
      let registry = GatewayRegistry::locate(&image).unwrap();
      let entry = registry.entry(registry.id(SEED).unwrap());
      assert_eq!(entry.handler, 0x3000);
      assert_eq!(entry.slots, [0x1200]);
   }

   #[test]
   fn walks_32_bit_flat_tables() {
      let mut image = image();
      image.pointer_width = 4;
      name(&mut image, 0x1000, SEED);
      name(&mut image, 0x1040, SPLIT_SEED);
      table(&mut image, 0x1200, 0x3000);
      let registry = GatewayRegistry::locate(&image).unwrap();
      assert_eq!(registry.entry(registry.id(SEED).unwrap()).handler, 0x3000);
      assert_eq!(registry.entry(registry.id(SPLIT_SEED).unwrap()).slots, [0x120C]);
   }

}

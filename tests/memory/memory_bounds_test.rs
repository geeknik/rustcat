use rustcat::debugger::memory::{MemoryMap, MemoryRegion, Protection};

#[test]
fn test_memory_region_bounds() {
    // Create a memory region that spans from 0x1000 to 0x2000 (4KB)
    let region = MemoryRegion::new(
        0x1000,
        0x1000,
        Protection::ReadWrite,
        Some("test_region".to_string()),
        false,
        true,
    );

    // Test address within bounds
    assert!(region.contains(0x1000)); // Start of region
    assert!(region.contains(0x1500)); // Middle of region
    assert!(region.contains(0x1FFF)); // End of region - 1

    // Test addresses outside bounds
    assert!(!region.contains(0x0FFF)); // Just before start
    assert!(!region.contains(0x2000)); // Just after end
    assert!(!region.contains(0x3000)); // Far after end
}

#[test]
fn test_memory_region_range() {
    let region = MemoryRegion::new(
        0x1000,
        0x1000,
        Protection::ReadWrite,
        Some("test_region".to_string()),
        false,
        true,
    );

    let range = region.range();
    assert_eq!(range.start, 0x1000);
    assert_eq!(range.end, 0x2000);
}

#[test]
fn test_memory_map_find_region() {
    let mut map = MemoryMap::new();
    
    // Add three regions with different addresses
    map.add_region(MemoryRegion::new(
        0x1000,
        0x1000,
        Protection::ReadWrite,
        Some("region1".to_string()),
        false,
        true,
    ));
    
    map.add_region(MemoryRegion::new(
        0x3000,
        0x1000,
        Protection::ReadExecute,
        Some("region2".to_string()),
        false,
        true,
    ));
    
    map.add_region(MemoryRegion::new(
        0x5000,
        0x2000,
        Protection::Read,
        Some("region3".to_string()),
        false,
        true,
    ));

    // Test finding regions by address
    let region1 = map.find_region(0x1500);
    assert!(region1.is_some());
    assert_eq!(region1.unwrap().base, 0x1000);
    
    let region2 = map.find_region(0x3500);
    assert!(region2.is_some());
    assert_eq!(region2.unwrap().base, 0x3000);
    
    let region3 = map.find_region(0x6000);
    assert!(region3.is_some());
    assert_eq!(region3.unwrap().base, 0x5000);

    // Test address not in any region
    let nonexistent = map.find_region(0x8000);
    assert!(nonexistent.is_none());
}

#[test]
fn test_protection_flags() {
    assert!(Protection::Read.can_read());
    assert!(!Protection::Read.can_write());
    assert!(!Protection::Read.can_execute());

    assert!(!Protection::Write.can_read());
    assert!(Protection::Write.can_write());
    assert!(!Protection::Write.can_execute());

    assert!(!Protection::Execute.can_read());
    assert!(!Protection::Execute.can_write());
    assert!(Protection::Execute.can_execute());

    assert!(Protection::ReadWrite.can_read());
    assert!(Protection::ReadWrite.can_write());
    assert!(!Protection::ReadWrite.can_execute());

    assert!(Protection::ReadExecute.can_read());
    assert!(!Protection::ReadExecute.can_write());
    assert!(Protection::ReadExecute.can_execute());

    assert!(!Protection::None.can_read());
    assert!(!Protection::None.can_write());
    assert!(!Protection::None.can_execute());
}

#[test]
fn test_memory_map_tracked_allocations() {
    let mut map = MemoryMap::new();
    
    // Track a few allocations
    map.track_allocation("heap_buffer", 0x8000, 0x100);
    map.track_allocation("stack_frame", 0x7000, 0x50);
    
    // Test finding allocations
    let tracked = map.get_tracked_allocations();
    assert_eq!(tracked.len(), 2);
    
    let heap_buffer = tracked.get("heap_buffer");
    assert!(heap_buffer.is_some());
    assert_eq!(heap_buffer.unwrap().0, 0x8000); // Address
    assert_eq!(heap_buffer.unwrap().1, 0x100);  // Size

    // Test removing an allocation
    assert!(map.untrack_allocation("heap_buffer"));
    assert_eq!(map.get_tracked_allocations().len(), 1);
    
    // Test removing non-existent allocation
    assert!(!map.untrack_allocation("nonexistent"));
}

// Test using proptest for fuzz-like property testing
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Test that a region always contains addresses within its bounds
        #[test]
        fn region_contains_all_addresses_within_bounds(
            base in 0x1000u64..0x10000u64,
            size in 1u64..0x10000u64,
            offset in 0u64..0x10000u64,
        ) {
            let region = MemoryRegion::new(
                base,
                size,
                Protection::ReadWrite,
                None,
                false,
                false,
            );

            // Only check if offset is within bounds to avoid overflow
            if offset < size {
                // Address within bounds
                assert!(region.contains(base + offset));
            }

            // Address before region
            if base > 0 {
                assert!(!region.contains(base - 1));
            }

            // Address after region
            assert!(!region.contains(base + size));
        }
    }
} 
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustcat::debugger::memory::{MemoryMap, MemoryRegion, Protection, MemoryFormat};

fn create_test_memory_map() -> MemoryMap {
    let mut map = MemoryMap::new();
    
    // Add a variety of regions that would be typical in a real program
    map.add_region(MemoryRegion::new(
        0x1000, 0x1000, Protection::ReadExecute, Some("code".to_string()), true, false
    ));
    
    map.add_region(MemoryRegion::new(
        0x2000, 0x2000, Protection::ReadWrite, Some("data".to_string()), true, false
    ));
    
    map.add_region(MemoryRegion::new(
        0x4000, 0x1000, Protection::ReadWrite, Some("heap".to_string()), false, true
    ));
    
    map.add_region(MemoryRegion::new(
        0x7000, 0x1000, Protection::ReadWrite, Some("stack".to_string()), false, true
    ));
    
    // Add many more regions to simulate a realistic process memory map
    for i in 0..100 {
        let base = 0x10000 + (i as u64 * 0x1000);
        map.add_region(MemoryRegion::new(
            base, 0x1000, Protection::ReadWrite, 
            Some(format!("region_{}", i)), false, true
        ));
    }
    
    // Track some allocations
    map.track_allocation("buffer1", 0x4100, 100);
    map.track_allocation("buffer2", 0x4200, 200);
    map.track_allocation("buffer3", 0x4300, 300);
    
    map
}

fn bench_memory_region_lookup(c: &mut Criterion) {
    let map = create_test_memory_map();
    
    // Create a group for region lookup benchmarks
    let mut group = c.benchmark_group("memory_region_lookup");
    
    // Benchmark finding a region that exists (best case)
    group.bench_function("find_existing_region", |b| {
        b.iter(|| black_box(map.find_region(0x4500)))
    });
    
    // Benchmark finding a region that doesn't exist (worst case)
    group.bench_function("find_nonexistent_region", |b| {
        b.iter(|| black_box(map.find_region(0xDEADBEEF)))
    });
    
    // Benchmark describing an address with a tracked allocation
    group.bench_function("describe_tracked_address", |b| {
        b.iter(|| black_box(map.describe_address(0x4150)))
    });
    
    group.finish();
}

fn bench_memory_formatting(c: &mut Criterion) {
    let map = create_test_memory_map();
    
    // Create test data
    let test_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    
    // Create a group for memory formatting benchmarks
    let mut group = c.benchmark_group("memory_formatting");
    
    // Benchmark different memory formatting options
    group.bench_function("format_hex", |b| {
        b.iter(|| black_box(map.format_memory(&test_data, MemoryFormat::Hex)))
    });
    
    group.bench_function("format_ascii", |b| {
        b.iter(|| black_box(map.format_memory(&test_data, MemoryFormat::Ascii)))
    });
    
    group.bench_function("format_u32", |b| {
        b.iter(|| black_box(map.format_memory(&test_data, MemoryFormat::U32)))
    });
    
    group.bench_function("format_f64", |b| {
        b.iter(|| black_box(map.format_memory(&test_data, MemoryFormat::F64)))
    });
    
    group.finish();
}

criterion_group!(benches, bench_memory_region_lookup, bench_memory_formatting);
criterion_main!(benches); 
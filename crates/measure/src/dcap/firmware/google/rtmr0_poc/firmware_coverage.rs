//! Offline firmware byte-coverage and CFV policy experiment.

use std::ops::Range;

use sha2::{Digest, Sha384};

use super::{
    CCEL,
    FIRMWARE,
    authenticated_firmware,
    check,
    quoted_registers,
    replay,
    rtmr0_digests,
};
use crate::dcap::tdvf::{cfv_sha384, mrtd_sha384, tdx_metadata_sections};

// Fixture-local layout inspection, not a general UEFI parser. Field
// definitions: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareFile.h
// https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/LzmaDecompress.h
// The observed name/file/compression GUIDs match the upstream
// FVMAIN_COMPACT layout in OvmfPkg/OvmfPkgX64.fdf. This does not identify
// Google's source commit.
//
// Separate manual inspection used Python's stdlib, without a test
// dependency:   data = lzma.decompress(firmware[0xa8:0x16a7db])
// It yielded 0xde0090 bytes. In that decompressed buffer, FV_IMAGE sections
// (type 0x17) at 0x7c and 0xe008c contain PEIFV [0x80, 0xe0080) and DXEFV
// [0xe0090, 0xde0090), with name GUIDs 6938079b-b503-4e3d-9d24-b28337a25806
// and 7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1. Their PeiCore and DxeCore files
// contain PE32 sections (type 0x10) at 0x1bc and 0xe0190 respectively.
// PeiCore's debug path at decompressed offset 0x108bc contains
// /build/work/eeea154c3ea9f6621a3a6be172c940339747/google3/ and
// Build/OvmfX64/DEBUG_CLANGDWARF/X64/MdeModulePkg/Core/Pei/PeiMain/DEBUG/
// PeiCore.dll. This is an embedded build identifier, not an established
// source revision. No matching source/disassembly proof of SEC measurement
// order was obtained.
fn compact_lzma_payload(volume_start: usize) -> Range<usize> {
    let fw = FIRMWARE;
    assert_eq!(&fw[volume_start + 40..volume_start + 44], b"_FVH");
    let volume_size =
        u64::from_le_bytes(fw[volume_start + 32..volume_start + 40].try_into().unwrap());
    let volume_end = volume_start.checked_add(usize::try_from(volume_size).unwrap()).unwrap();
    assert!(volume_end <= fw.len());
    let header_size =
        u16::from_le_bytes(fw[volume_start + 48..volume_start + 50].try_into().unwrap());
    assert!(header_size >= 56);
    let extension_offset =
        u16::from_le_bytes(fw[volume_start + 52..volume_start + 54].try_into().unwrap()) as usize;
    assert!(extension_offset >= header_size as usize);
    let extension = volume_start + extension_offset;
    assert!(extension + 20 <= volume_end);
    // FVMAIN_COMPACT's name GUID in the inspected fixture; also used
    // upstream.
    assert_eq!(
        &fw[extension..extension + 16],
        &[
            0x17, 0x5e, 0xdb, 0x48, 0x7c, 0x70, 0x2d, 0x47, 0x91, 0xcd, 0x16, 0x13, 0xe7, 0xef,
            0x51, 0xb0,
        ]
    );
    let mut file = (volume_start + header_size as usize + 7) & !7;
    loop {
        assert!(file + 24 <= volume_end, "FV image file not found");
        let size = u32::from_le_bytes([fw[file + 20], fw[file + 21], fw[file + 22], 0]) as usize;
        assert!(size >= 24 && size != 0xff_ffff && file + size <= volume_end);
        if fw[file + 18] == 0xf0 {
            // skip FFS padding files
            file = (file + size + 7) & !7;
            continue;
        }
        assert_eq!(fw[file + 18], 0x0b, "expected firmware-volume image file");
        let section = file + 24;
        let section_size =
            u32::from_le_bytes([fw[section], fw[section + 1], fw[section + 2], 0]) as usize;
        assert!(section_size >= 24 && section + section_size <= file + size);
        assert_eq!(fw[section + 3], 0x02, "GUID-defined section");
        assert_eq!(
            &fw[section + 4..section + 20],
            &[
                0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94,
                0x03, 0xcf,
            ],
            "LZMA custom decompression GUID"
        );
        let offset =
            u16::from_le_bytes(fw[section + 20..section + 22].try_into().unwrap()) as usize;
        let attributes = u16::from_le_bytes(fw[section + 22..section + 24].try_into().unwrap());
        assert!(offset >= 24 && offset + 13 < section_size);
        assert_eq!(attributes & 1, 1, "processing required");
        println!(
            "FVMAIN_COMPACT: {volume_start:#x}..{volume_end:#x}; FV image file {file:#x}; GUID-defined LZMA section {section:#x}..{:#x}; payload {:#x}..{:#x}",
            section + section_size,
            section + offset,
            section + section_size
        );
        return section + offset..section + section_size;
    }
}

#[test]
fn cfv_mutation_is_invisible_to_mrtd_but_rejected_by_cfv_policy() {
    // Authenticate the original bytes before any in-memory mutations.
    let baseline = authenticated_firmware();
    let (quoted_mrtd, quoted_rtmr0) = quoted_registers();
    let original_digests = rtmr0_digests(CCEL).unwrap();
    assert_eq!(original_digests.get(1), Some(&baseline.cfv));
    check(&original_digests, quoted_rtmr0, baseline.cfv).unwrap();

    let sections = tdx_metadata_sections(FIRMWARE).unwrap();
    println!("kind | file offset | raw size | GPA | memory size | attributes");
    for s in &sections {
        println!(
            "{} | {:#x} | {:#x} | {:#x} | {:#x} | {:#x}",
            s.kind,
            s.image_offset,
            s.raw_data_size,
            s.memory_address,
            s.memory_data_size,
            s.attributes
        );
        assert!((s.image_offset as u64 + s.raw_data_size as u64) <= FIRMWARE.len() as u64);
    }
    let cfvs: Vec<_> = sections.iter().filter(|s| s.kind == 1).collect();
    assert_eq!(cfvs.len(), 1, "this experiment requires an unambiguous CFV descriptor");
    let cfv = cfvs[0];
    assert_ne!(cfv.raw_data_size, 0);
    let cfv_range =
        cfv.image_offset as usize..(cfv.image_offset as usize + cfv.raw_data_size as usize);

    // Mirror the actual content coverage in mrtd_sha384, including
    // overlaps: MR_EXTEND hashes memory_size / 4096 full pages, not
    // raw_data_size. MEM.PAGE.ADD hashes operation/address information,
    // not file contents.
    let measured: Vec<Range<usize>> = sections
        .iter()
        .filter(|s| s.attributes & 1 != 0)
        .map(|s| {
            let bytes = usize::try_from((s.memory_data_size / 4096) * 4096).unwrap();
            let start = s.image_offset as usize;
            let end = start.checked_add(bytes).unwrap();
            assert!(end <= FIRMWARE.len());
            start..end
        })
        .collect();
    for r in &measured {
        println!("MRTD file-content coverage: {:#x}..{:#x}", r.start, r.end);
    }

    // Locate this fixture's descriptor header only to protect structures
    // during mutation selection. The existing TDVF parser supplies all
    // section fields. Conservatively protect everything from the
    // descriptor through the footer.
    let mut header = b"TDVF".to_vec();
    header.extend((16u32 + 32 * sections.len() as u32).to_le_bytes());
    header.extend(1u32.to_le_bytes());
    header.extend((sections.len() as u32).to_le_bytes());
    let metadata =
        FIRMWARE.windows(header.len()).rposition(|w| w == header).expect("TDVF header missing");
    let protected = metadata..FIRMWARE.len();
    println!("Protected metadata/footer: {:#x}..{:#x}", protected.start, protected.end);
    let payload = compact_lzma_payload(cfv_range.start);
    assert!(
        cfv_range.contains(&payload.start) && cfv_range.end < payload.end,
        "expected CFV to contain the start, but not all, of the compressed payload"
    );
    // Skip the 13-byte LZMA-alone header; change compressed content rather
    // than a descriptor, volume header or compression header. No boot
    // is attempted.
    let mutation_offset = (payload.start + 13..payload.end)
        .find(|offset| {
            cfv_range.contains(offset) &&
                !protected.contains(offset) &&
                !measured.iter().any(|r| r.contains(offset))
        })
        .expect("premise unsupported: no unmeasured CFV payload byte outside metadata/footer");
    let control_offset = measured
        .iter()
        .flat_map(|r| r.clone())
        .find(|offset| !cfv_range.contains(offset) && !protected.contains(offset))
        .expect(
            "no measured file-content byte outside CFV and metadata/footer for positive control",
        );

    // Snapshot every parsed field without changing Section's production
    // API.
    let descriptors = |blob: &[u8]| {
        tdx_metadata_sections(blob)
            .unwrap()
            .into_iter()
            .map(|s| {
                (
                    s.image_offset,
                    s.raw_data_size,
                    s.memory_address,
                    s.memory_data_size,
                    s.kind,
                    s.attributes,
                )
            })
            .collect::<Vec<_>>()
    };
    let original_descriptors = descriptors(FIRMWARE);
    assert_eq!(mrtd_sha384(FIRMWARE).unwrap(), baseline.mrtd);
    assert_eq!(cfv_sha384(FIRMWARE).unwrap(), baseline.cfv);

    let mut modified = FIRMWARE.to_vec();
    modified[mutation_offset] ^= 1;
    assert_ne!(modified, FIRMWARE);
    // This no longer matches the signed whole-file digest. We do not claim
    // that Google endorsed the mutation or that GCP would launch it.
    assert_ne!(Sha384::digest(&modified), Sha384::digest(FIRMWARE));
    assert_eq!(descriptors(&modified), original_descriptors);
    assert_eq!(&modified[protected.clone()], &FIRMWARE[protected.clone()]);
    let modified_mrtd = mrtd_sha384(&modified).unwrap();
    let modified_cfv = cfv_sha384(&modified).unwrap();
    assert_eq!(modified_mrtd, baseline.mrtd);
    assert_eq!(modified_mrtd, quoted_mrtd);
    assert_ne!(modified_cfv, baseline.cfv);

    let mut control = FIRMWARE.to_vec();
    control[control_offset] ^= 1;
    assert_eq!(descriptors(&control), original_descriptors);
    assert_eq!(&control[protected.clone()], &FIRMWARE[protected]);
    let control_mrtd = mrtd_sha384(&control).unwrap();
    let control_cfv = cfv_sha384(&control).unwrap();
    assert_ne!(control_mrtd, baseline.mrtd);
    assert_eq!(control_cfv, baseline.cfv);

    // Synthetic post-mutation list/target, NOT a new quote or an actual
    // boot. Its replay matches, so rejection specifically comes from
    // CFV policy.
    let mut synthetic_digests = original_digests.clone();
    synthetic_digests[1] = modified_cfv;
    let synthetic_target = replay(&synthetic_digests);
    check(&synthetic_digests, synthetic_target, modified_cfv).unwrap();
    assert_eq!(
        check(&synthetic_digests, synthetic_target, baseline.cfv),
        Err("second extension is not endorsed CFV")
    );

    println!(
        "CFV range {:#x}..{:#x}, attributes {:#x}; mutation {mutation_offset:#x}, control {control_offset:#x}",
        cfv_range.start, cfv_range.end, cfv.attributes
    );
    for (label, mrtd, cfv) in [
        ("original", baseline.mrtd, baseline.cfv),
        ("CFV mutation", modified_mrtd, modified_cfv),
        ("measured control", control_mrtd, control_cfv),
    ] {
        println!("{label}: MRTD={} CFV={}", hex::encode(mrtd), hex::encode(cfv));
    }
    println!(
        "CFV covers the start, not the full LZMA payload ({:#x}..{:#x}). Quote is parsed, not cryptographically verified; SEC measurement/execution order remains unproven.",
        payload.start, payload.end
    );
}

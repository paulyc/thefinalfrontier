//
//  exfat_defs.h - ExFAT filesysytem structures
//  thefinalfrontier
//
//  Created by on 5 November 2019.
//
//  Copyright (C) 2019 Paul Ciarlo <paul.ciarlo@gmail.com>.
//
//  See LICENSE for terms.

#ifndef _github_paulyc_exfat_structs_hpp_
#define _github_paulyc_exfat_structs_hpp_

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>

#warning Yeah this only applies to MY disk. Work in progress. First I have to get my files off my disk
#define EXFAT_BYTES_PER_SECTOR 512
#define EXFAT_SECTORS_PER_CLUSTER 512
#define EXFAT_BYTES_PER_CLUSTER (512*512)
#define EXFAT_BYTES_PER_NODE_ENTRY 32
#define EXFAT_TOTAL_SECTORS 7813560247
#define EXFAT_PARTITION_START_SECTOR 0x64028
#define EXFAT_CLUSTER_HEAP_START_SECTOR_PARTITION_START_OFFSET 0x283D8
#define EXFAT_CLUSTER_HEAP_START_SECTOR_ABSOLUTE (EXFAT_PARTITION_START_SECTOR + 0x283D8)
#define EXFAT_CLUSTERS_IN_FAT ((EXFAT_TOTAL_SECTORS - EXFAT_CLUSTER_HEAP_START_SECTOR_PARTITION_START_OFFSET) / EXFAT_BYTES_PER_SECTOR)
#define EXFAT_BYTES_PER_DISK ((EXFAT_TOTAL_SECTORS + EXFAT_PARTITION_START_SECTOR) * EXFAT_BYTES_PER_SECTOR)

enum ExfatAttributeFlags {
    READ_ONLY   = 1<<0,
    HIDDEN      = 1<<1,
    SYSTEM      = 1<<2,
    VOLUME      = 1<<3,
    DIRECTORY   = 1<<4,
    ARCH        = 1<<5
};

struct exfat_bios_parameter_block {
} __attribute__((packed));

struct exfat_sector
{
    uint8_t data[EXFAT_BYTES_PER_SECTOR];
} __attribute__((packed));
static_assert(sizeof(struct sector) == EXFAT_BYTES_PER_SECTOR);

struct exfat_cluster
{
    struct exfat_sector sectors[EXFAT_SECTORS_PER_CLUSTER];
} __attribute__((packed));
static_assert(sizeof(struct exfat_cluster) == EXFAT_BYTES_PER_CLUSTER);

enum ExfatVolumeFlags {
    NO_FLAGS            = 0,
    SECOND_FAT_ACTIVE   = 1<<0,
    VOLUME_DIRTY        = 1<<1, // probably in an inconsistent state
    MEDIA_FAILURE       = 1<<2, // failed read/write and exhausted retry algorithms
    CLEAR_TO_ZERO       = 1<<3  // clear this bit to zero on mount
    // rest are reserved
};

struct exfat_boot_sector {
    uint8_t  jump_boot[3]              = {0x90, 0x76, 0xEB};   // 0xEB7690 little-endian
    uint8_t  fs_name[8]                = {'E', 'X', 'F', 'A', 'T', '\x20', '\x20', '\x20'};
    uint8_t  zero[53]                  = {0};
    uint64_t partition_offset_sectors  = 0;        // Sector address of partition on media (0 to ignore)
    uint64_t volume_length_sectors;                // Size of ExFAT volume in sectors
    uint32_t fat_offset_sectors;                   // 24 <= Sector offset of FAT <= ClusterHeapOffset - FatLength
    uint32_t fat_length_sectors;                   // Size of (each)FAT in sectors
    uint32_t cluster_heap_offset_sectors;          // FatOffset + FatLength <= Offset of Cluster Heap
    uint32_t cluster_count;                        // Number of clusters in cluster heap
    uint32_t root_directory_cluster;               // 2 <= Cluster address of root directory
    uint32_t volume_serial_number      = 0xdead;   // All values are valid!
    uint16_t fs_revision               = 0x0100;
    uint16_t volume_flags              = NO_FLAGS; // Combination of fs_volume_flags_t
    uint8_t  log2_bytes_per_sector;                // eg, log2(512) == 9, 512<= bytes_per_sector <= 4096 so range [9,12]
    uint8_t  log2_sectors_per_cluster;             // at least 0, at most 25-log2_bytes_per_sector (32MB max cluster size)
    uint8_t  num_fats                   = 1;       // 1 or 2. 2 onlyfor TexFAT (not supported)
    uint8_t  drive_select               = 0x80;    // Extended INT 13h drive number
    uint8_t  percent_used               = 0xFF;    // [0,100] Percentage of heap in use or 0xFF if not available
    uint8_t  reserved[7]                = {0};
    uint8_t  boot_code[390]             = {0xF4};  // x86 HLT instruction
    uint16_t boot_signature             = 0xAA55;
	uint8_t  padding[EXFAT_BYTES_PER_SECTOR - 512];            // Padded out to sector size
} __attribute__((packed));
static_assert(sizeof(struct exfat_boot_sector) == EXFAT_BYTES_PER_SECTOR);

// for a 512-byte sector. should be same size as a sector
struct exfat_extended_boot_structure {
    uint8_t  extended_boot_code[EXFAT_BYTES_PER_SECTOR - 4] = {0};
    uint32_t extended_boot_signature = 0xAA550000;
} __attribute__((packed));
static_assert(sizeof(struct exfat_extended_boot_structure) == EXFAT_BYTES_PER_SECTOR);

struct exfat_main_extended_boot_region {
    struct exfat_extended_boot_structure ebs[8];
} __attribute__((packed));
static_assert(sizeof(struct exfat_main_extended_boot_region) == 8*EXFAT_BYTES_PER_SECTOR);

struct exfat_oem_parameters_null_entry {
    uint8_t guid[16]     = {0};
    uint8_t reserved[32] = {0};
} __attribute__((packed));
static_assert(sizeof(struct exfat_oem_parameters_null_entry) == 48);

// First 16 bytes of each field is a GUID and remaining 32 bytes are the parameters (undefined)
struct exfat_oem_parameters {
    struct exfat_oem_parameters_null_entry null_entries[10];
    uint8_t reserved[EXFAT_BYTES_PER_SECTOR - 480]  = {0}; // 32-3616 bytes padded out to sector size
} __attribute__((packed));
static_assert(sizeof(struct exfat_oem_parameters) == EXFAT_BYTES_PER_SECTOR);

// one example of a parameter that would go in an OEM parameter but it's not used
struct exfat_flash_parameters {
    uint8_t  OemParameterType[16];
    uint32_t EraseBlockSize;
    uint32_t PageSize;
    uint32_t NumberOfSpareBlocks;
    uint32_t tRandomAccess;
    uint32_t tProgram;
    uint32_t tReadCycle;
    uint32_t tWriteCycle;
    uint8_t  Reserved[4];
} __attribute__((packed));
static_assert(sizeof(struct exfat_flash_parameters) == 48);

struct exfat_timestamp {
    uint8_t double_seconds[5];
    uint8_t minute[6];
    uint8_t hour[5];
    uint8_t month[4];
    uint8_t year[7];
} __attribute__((packed));

struct exfat_file_attributes {
    uint8_t read_only;      // 1 = read only
    uint8_t hidden;         // 1 = hidden
    uint8_t system;         // 1 = system
    uint8_t reserved0       = 0;
    uint8_t directory;      // 0 = file 1 = directory
    uint8_t archive;
    uint8_t reserved1[10]   = {0};
} __attribute__((packed));

enum ExfatMetadataEntryFlags {
    VALID       = 0x80,
    CONTINUED   = 0x40,
    OPTIONAL    = 0x20
};

enum ExfatMetadataEntryType {
    END_OF_DIRECTORY    = 0x00,
    ALLOCATION_BITMAP   = 0x01 | VALID,                         // 0x81
    UPCASE_TABLE        = 0x02 | VALID,                         // 0x82
    VOLUME_LABEL        = 0x03 | VALID,                         // 0x83
    FILE_DIR_ENTRY      = 0x05 | VALID,                         // 0x85
    VOLUME_GUID         = 0x20 | VALID,                         // 0xA0
    TEXFAT_PADDING      = 0x21 | VALID,                         // 0xA1
    WINDOWS_CE_ACT      = 0x22 | VALID,                         // 0xA2
    STREAM_EXTENSION    = 0x00 | VALID | CONTINUED,             // 0xC0
    FILE_NAME           = 0x01 | VALID | CONTINUED,             // 0xC1
    WINDOWS_CE_ACL      = 0x02 | VALID | CONTINUED,             // 0xC2
    FILE_TAIL           = 0x00 | VALID | CONTINUED | OPTIONAL,  // 0xE0
};

enum ExfatFileFlags {
    ALLOC_POSSIBLE  = 1<<0, // if 0, first cluster and data length will be undefined in directory entry
    CONTIGUOUS      = 1<<1
};

enum ExfatVolumeGuidFlags {
    ALLOCATION_POSSIBLE = 1<<0, // must be 0
    NO_FAT_CHAIN        = 1<<1  // must be 0
};

struct exfat_raw_entry {
    uint8_t type;
    uint8_t data[31];
} __attribute__((packed));
static_assert(sizeof(struct exfat_raw_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_file_directory_entry {
    uint8_t  type               = FILE_DIR_ENTRY;   // FILE_DIR_ENTRY = 0x85
    uint8_t  continuations; // between 2 and 18
    uint16_t checksum;
    uint16_t attributes;
    uint8_t  reserved0[2]       = {0};
    uint16_t created_time;
    uint16_t created_date;
    uint16_t modified_time;
    uint16_t modified_date;
    uint16_t accessed_time;
    uint16_t accessed_date;
    uint8_t  created_time_cs;
    uint8_t  modified_time_cs;
    uint8_t  accessed_time_cs;
    uint8_t  reserved1[9]       = {0};
} __attribute__((packed));
static_assert(sizeof(struct file_directory_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

bool exfat_file_directory_entry_is_valid(struct exfat_file_directory_entry *ent);
uint16_t exfat_file_directory_entry_calc_set_checksum(struct exfat_file_directory_entry *ent);

struct exfat_primary_directory_entry {
    uint8_t  type;              // one of fs_directory_entry_t
    uint8_t  secondary_count;   // 0 - 255, number of children in directory
    uint16_t set_checksum;      // checksum of directory entries in this set, excluding this field
    uint16_t primary_flags;     // combination of fs_file_flags_t
    uint8_t  reserved[14] = {0};
    uint32_t first_cluster;     /* 0 = does not exist, otherwise, in range [2,ClusterCount+1] */
    uint64_t data_length;
} __attribute__((packed));
static_assert(sizeof(struct exfat_primary_directory_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_secondary_directory_entry {
    uint8_t  type;              // one of fs_directory_entry_t
    uint8_t  secondary_flags;   // combination of fs_file_flags_t
    uint8_t  reserved[18]   = {0};
    uint32_t first_cluster;     /* 0 = does not exist, otherwise, in range [2,ClusterCount+1] */
    uint64_t data_length;
} __attribute__((packed));
static_assert(sizeof(struct exfat_secondary_directory_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_stream_extension_entry {
    uint8_t type            = STREAM_EXTENSION;
    uint8_t flags;          // Combination of fs_file_flags_t
    uint8_t reserved0       = 0;
    uint8_t name_length;
    uint16_t name_hash;
    uint16_t reserved1      = 0;
    uint64_t valid_size;
    uint32_t reserved2      = 0;
    uint32_t first_cluster;     /* 0 = does not exist, otherwise, in range [2,ClusterCount+1] */
    uint64_t size;
} __attribute__((packed));
static_assert(sizeof(struct exfat_stream_extension_entry) == EXFAT_BYTES_PER_NODE_ENTRY);
bool exfat_stream_extension_entry_is_valid(struct exfat_stream_extension_entry *ent);

#define EXFAT_FS_FILE_NAME_ENTRY_SIZE 15
struct exfat_file_name_entry {
    uint8_t type        = FILE_NAME;
    uint8_t reserved    = 0;
    int16_t name[EXFAT_FS_FILE_NAME_ENTRY_SIZE];
} __attribute__((packed));
static_assert(sizeof(struct exfat_file_name_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_allocation_bitmap_entry {
    uint8_t type            = ALLOCATION_BITMAP;
    uint8_t bitmap_flags    = 0; // 0 if first allocation bitmap, 1 if second (TexFAT only)
    uint8_t reserved[18]    = {0};
    uint32_t first_cluster  = 2;      /* 0 = does not exist, otherwise, in range [2,ClusterCount+1] */
    uint64_t data_length;   // Size of allocation bitmap in bytes. Ceil(ClusterCount / 8)
} __attribute__((packed));
static_assert(sizeof(struct exfat_allocation_bitmap_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_volume_guid_entry {
    uint8_t  type               = VOLUME_GUID; // 0xA0
    uint8_t  secondary_count    = 0;
	uint16_t set_checksum       = 0;
    uint16_t flags              = 0;           // combination of VolumeGuidFlags, must be 0
	uint8_t  volume_guid[16]    = {0};         // must not be null
    uint8_t  reserved[10]       = {0};
} __attribute__((packed));
static_assert(sizeof(struct exfat_volume_guid_entry) == EXFAT_BYTES_PER_NODE_ENTRY);

#define EXFAT_VOLUME_LABEL_MAX_LENGTH 11
struct volume_label_entry_t {
    static constexpr size_t  = 11;
    constexpr volume_label_entry_t() {}
    constexpr volume_label_entry_t(const std::basic_string<char16_t> &volume_label_utf16) { set_label(volume_label_utf16); }

    void set_label(const std::basic_string<char16_t> &volume_label_utf16) {
        character_count = std::min(VOLUME_LABEL_MAX_LENGTH, volume_label_utf16.length());
        memcpy(volume_label, volume_label_utf16.data(), sizeof(char16_t) * character_count);
    }

    uint8_t type                                    = VOLUME_LABEL; // 0x83 if volume label exists or 0x03 if it was deleted
    uint8_t character_count                         = 0;            // characters in label
    uint16_t volume_label[VOLUME_LABEL_MAX_LENGTH]  = {0};
    uint8_t reserved[8]                             = {0};
} __attribute__((packed));
static_assert(sizeof(struct volume_label_entry_t) == EXFAT_BYTES_PER_NODE_ENTRY);

struct upcase_table_entry_t {
    uint8_t  type           = UPCASE_TABLE; // 0x82
    uint8_t  reserved0[3]   = {0};
    uint32_t checksum;
    uint8_t  reserved1[12]  = {0};
    uint32_t first_cluster  = 3;      /* 0 = does not exist, otherwise, in range [2,ClusterCount+1] */
    uint64_t data_length;
} __attribute__((packed));
static_assert(sizeof(struct upcase_table_entry_t) == EXFAT_BYTES_PER_NODE_ENTRY);

union exfat_metadata_entry_u {
    struct exfat_raw_entry raw;
    struct exfat_file_directory_entry file_directory_entry;
    struct exfat_primary_directory_entry primary_directory_entry;
    struct exfat_secondary_directory_entry secondary_directory_entry;
    struct exfat_stream_extension_entry stream_extension_entry;
    struct exfat_file_name_entry file_name_entry;
    struct exfat_allocation_bitmap_entry allocation_bitmap_entry;
    struct exfat_volume_guid_entry volume_guid_entry;
    struct exfat_volume_label_entry volume_label_entry;
    struct exfat_upcase_table_entry upcase_table_entry;
} __attribute__((packed));
static_assert(sizeof(union exfat_metadata_entry_u) == EXFAT_BYTES_PER_NODE_ENTRY);

struct exfat_allocation_bitmap_table
{
    static constexpr size_t BitmapSize = NumClusters & 0x7 ? (NumClusters >> 3) + 1 : NumClusters >> 3;
    //static constexpr size_t ClusterSize = SectorSize * SectorsPerCluster;
    //static constexpr size_t PaddingSize = ClusterSize - BitmapSize;

    // first bit in the bitmap (cluster 2) is the lowest-order byte
	uint8_t bitmap[BitmapSize] = {0};
	//uint8_t padding[PaddingSize] = {0};

	constexpr allocation_bitmap_table_t() {
		mark_all_alloc();
	}

	void mark_all_alloc() {
		for (size_t i = 0; i < BitmapSize; ++i) {
			bitmap[i] = 0xFF;
		}
	}

    constexpr allocation_bitmap_entry_t get_directory_entry() const {
        return allocation_bitmap_entry_t {
            .data_length = BitmapSize
        };
    }
} __attribute__((packed));
static_assert(sizeof(struct allocation_bitmap_table_t<29806>) == 3726);

template <int SectorSize, int NumEntries>
struct upcase_table_t {
    constexpr upcase_table_t() {
		unsigned i = 0;
        for (; i < 0x61; ++i) {
            entries[i] = i;
        }
        for (; i <= 0x7B; ++i) {
            // a-z => A=>z (0x61-0x7a => 0x41-0x5a, clear 0x20 bit)
            entries[i] = i ^ 0x20; // US-ASCII letters
        }
        for (; i < 0xE0; ++i) {
            entries[i] = i;
        }
        for (; i < 0xFF; ++i) {
            if (i == 0xD7 || i == 0xF7) { // multiplication and division signs
                entries[i] = i;
            } else {
                entries[i] = i ^ 0x20; // ISO-8859-1 letters with diacritics
            }
        }
    }
    char16_t entries[NumEntries];

    constexpr upcase_table_entry_t get_directory_entry() const {
        const uint8_t *data = (const uint8_t*)entries;
        size_t sz_bytes = sizeof(char16_t) * NumEntries;
        uint32_t chksum = 0;

        for (size_t i = 0; i < sz_bytes; ++i) {
            chksum = (((chksum<<31) & 0x80000000) | (chksum >> 1)) + (uint32_t)data[i];
        }

        return upcase_table_entry_t {
            .checksum = chksum,
            .data_length = sz_bytes,
        };
    }
} __attribute__((packed));
static_assert(sizeof(struct exfat_file_directory_entry) == 32);

struct exfat_reserved_sector {
    uint8_t reserved[EXFAT_BYTES_PER_SECTOR] = {0};
} __attribute__((packed));
static_assert(sizeof(struct exfat_reserved_sector) == EXFAT_BYTES_PER_SECTOR);

struct exfat_boot_checksum_sector {
    uint32_t checksum[SectorSize / 4]; // same 32-bit checksum thing repeated

    void fill_checksum(uint8_t *vbr, size_t vbr_size)
    {
        assert(vbr_size == SectorSize * 11);

        uint32_t chksum = 0;
        for (size_t i = 0; i < vbr_size; ++i) {
            if (i != 106 && i != 107 && i != 112) {
                chksum = (((chksum << 31) &0x80000000) | (chksum >> 1)) + (uint32_t)vbr[i];
            }
        }
        for (size_t i = 0; i < sizeof(checksum); ++i) {
            checksum[i] = chksum;
        }
    }
} __attribute__((packed));
static_assert(sizeof(struct exfat_boot_checksum_sector) == EXFAT_BYTES_PER_SECTOR);

struct exfat_boot_region {
    struct exfat_boot_sector               vbr;            // Sector 0
    struct exfat_main_extended_boot_region mebs;           // Sector 1-8
    struct exfat_oem_parameters            oem_params;     // Sector 9
    struct exfat_reserved_sector           reserved;       // Sector 10
    struct exfat_boot_checksum_sector      checksum;       // Sector 11
} __attribute__((packed));
static_assert(sizeof(struct exfat_boot_region) == 12*EXFAT_BYTES_PER_SECTOR);

enum FatEntrySpecial {
    BAD_CLUSTER                 = 0xFFFFFFF7,
    MEDIA_DESCRIPTOR_HARD_DRIVE = 0xFFFFFFF8,
    END_OF_FILE                 = 0xFFFFFFFF
};

#define EXFAT_BYTES_PER_FILE_ALLOCATION_TABLE ((EXFAT_CLUSTERS_IN_FAT + 2) * sizeof(uint32_t))
#define EXFAT_FILE_ALLOCATION_TABLE_PADDING_BYTES (EXFAT_BYTES_PER_SECTOR - (EXFAT_BYTES_PER_FILE_ALLOCATION_TABLE % EXFAT_BYTES_PER_SECTOR))

struct exfat_file_allocation_table
{
    uint32_t media_type             = MEDIA_DESCRIPTOR_HARD_DRIVE;
    uint32_t reserved               = END_OF_FILE;   // Must be 0xFFFFFFFF
    uint32_t entries[EXFAT_CLUSTERS_IN_FAT] = {END_OF_FILE}; // ??
    uint8_t  padding[EXFAT_FILE_ALLOCATION_TABLE_PADDING_BYTES]   = {0}; // pad to sector
} __attribute__((packed));

struct exfat_root_directory
{
    struct exfat_volume_label_entry        label_entry;
    struct exfat_allocation_bitmap_entry   bitmap_entry;
    struct exfat_upcase_table_entry        upcase_entry;
    struct exfat_volume_guid_entry         guid_entry;
    struct exfat_file_directory_entry      directory_entry;
    struct exfat_stream_extension_entry    ext_entry;
    struct exfat_file_name_entry           name_entry;
    struct exfat_secondary_directory_entry directory_entries[0]; // dynamically sized based on number of child entities
} __attribute__((packed));

struct exfat_directory
{
    struct exfat_primary_directory_entry primary_entry;
    struct exfat_secondary_directory_entry secondary_entries[0];
} __attribute__((packed));

struct exfat_cluster_heap
{
    struct exfat_cluster storage[EXFAT_CLUSTERS_IN_FAT];
} __attribute__((packed));

struct exfat_fat_region {
    constexpr static size_t cluster_heap_start_sector = 0x283D8;
    constexpr static size_t fat_heap_alignment_sectors = EXFAT_CLUSTER_HEAP_START_SECTOR_PARTITION_START_OFFSET -
        (2 * sizeof(boot_region_t<SectorSize>) + // 24 sectors = 12288 bytes
        sizeof(file_allocation_table_t<SectorSize, SectorsPerCluster, ClustersInFat>)) / SectorSize;

    file_allocation_table_t<SectorSize, SectorsPerCluster, ClustersInFat> fat;
    sector_t<SectorSize> fat_cluster_heap_alignment[fat_heap_alignment_sectors];
} __attribute__((packed));

struct exfat_data_region {
    constexpr static size_t ExcessSectors = NumSectors - ClustersInFat * SectorsPerCluster;

    cluster_heap_t<SectorSize, SectorsPerCluster, ClustersInFat> cluster_heap;
    sector_t<SectorSize> excess_space[ExcessSectors];
} __attribute__((packed));

struct exfat_filesystem {
    constexpr static size_t ClusterSize = SectorSize * SectorsPerCluster;
    constexpr static size_t ClustersInFat = (NumSectors - 0x283D8) / 512;
    exfat_boot_region                                                  main_boot_region;
    // copy of main_boot_region
    exfat_boot_region                                                  backup_boot_region;
    struct exfat_fat_region                 fat_region;
    //root directory is in the cluster heap
    struct exfat_data_region    data_region;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif /* _github_paulyc_exfat_structs_hpp_ */


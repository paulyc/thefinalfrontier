//
//  exfat_defs.c - ExFAT filesysytem structures
//
//  thefinalfrontier
//
//  Copyright (C) 2019 Paul Ciarlo <paul.ciarlo@gmail.com>
//
//  Created on 5 November 2019.
//
//  See LICENSE for terms.
//

#include "exfat_defs.h"

bool exfat_file_directory_entry_is_valid(struct exfat_file_directory_entry *ent) {
    if (ent->type != FILE_DIR_ENTRY) return false;
    if (ent->continuations < 2 || ent->continuations > 18) return false;
    return true;
}

uint16_t exfat_file_directory_entry_calc_set_checksum(struct exfat_file_directory_entry *ent) {
     int file_info_size = (ent->continuations + 1) * 32;
     uint8_t *bufp = (uint8_t*)ent;
     uint16_t chksum = 0;

     for (int i = 0; i < file_info_size; ++i) {
         if (i != 2 && i != 3) {
            chksum = (((chksum << 15) & 0x8000) | (chksum >> 1)) + (uint16_t)bufp[i];
        }
    }
    return chksum;
}

bool exfat_stream_extension_entry_is_valid(struct exfat_stream_extension_entry *ent) {
    return ent->type == STREAM_EXTENSION;
}

constexpr volume_guid_entry_t() {
    for (size_t i = 0; i < 16; ++i) {
        volume_guid[i] = 0;
    }
    this->set_checksum = this->calc_checksum();
}
constexpr volume_guid_entry_t(const uint8_t guid[16]) {
    for (size_t i = 0; i < 16; ++i) {
        volume_guid[i] = guid[i];
    }
    this->set_checksum = this->calc_checksum();
}

// got to check this algo
uint16_t exfat_volume_guid_entry_calc_checksum(struct exfat_volume_guid_entry *ent) const {
    const uint8_t *data = (const uint8_t *)ent;
    uint16_t set_checksum = 0;
    for (size_t i = 0; i < sizeof(struct exfat_volume_guid_entry); i++) {
        if (i != 2 && i != 3) {
            set_checksum = (set_checksum << 31) | (set_checksum >> 1) + data[i];
        }
    }
    return set_checksum;
}

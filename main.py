import os
import struct
import sys
from decompress import decompress_xpress_huff
from structs import MAMHeader, parse_file_information_header, parse_volume_information_entry
from logger import logger

# File header = 8 bytes
# Uncompressed File header = 84 bytes
# File information = 212 bytes (This starts at offset 84)
# Volume information entries = 96 bytes each
# Directory strings = variable length determined by Array of UTF-16 little-endian strings with end-of-string character

if len(sys.argv) != 2:
    print("Usage: python main.py <prefetch_file_path>")
    sys.exit(1)

prefetch_file_path = sys.argv[1]

with open(prefetch_file_path, 'rb') as f:
    prefetch_file = f.read()

def read_mam_header(prefetch_file):
    signature, uncompressed_size = struct.unpack('<4sI', prefetch_file[0:8])
    mam_header = MAMHeader(signature, uncompressed_size)
    print("MAM Header:")
    print(f"    Signature: {mam_header.signature}")
    print(f"    Uncompressed Size: {mam_header.uncompressed_size}")
    return mam_header

def MAM_to_SCCA(prefetch_file):
    result = decompress_xpress_huff(prefetch_file)
    if result is not None:
        mam_header, uncompressed_data, scca_data = result
        return uncompressed_data, scca_data
    return None, None

def read_uncompressed_file_header(SCCA_data):
    print("\nUncompressed File Header:")
    print(f"    Format Version: {SCCA_data.format_version}")
    print(f"    Signature: {SCCA_data.signature}")
    print(f"    Unknown1: 0x{SCCA_data.unknown1:08x}")
    print(f"    File Size: {SCCA_data.file_size}")
    print(f"    Executable Filename: {SCCA_data.executable_filename}")
    print(f"    Prefetch Hash: 0x{SCCA_data.prefetch_hash:08x}")
    print(f"    Unknown Flags: 0x{SCCA_data.unknown_flags:08x}")

def read_file_information_header(uncompressed_data):
    """
    Read and display the file information header from uncompressed prefetch data.
    
    Args:
        uncompressed_data (bytes): The uncompressed prefetch file data
    """
    try:
        file_info_header = parse_file_information_header(uncompressed_data)
        print("\nFile Information Header:")
        print(f"    File Metrics Array Offset: {file_info_header.file_metrics_array_offset}")
        print(f"    Number of File Metrics Entries: {file_info_header.num_file_metrics_entries}")
        print(f"    Trace Chains Array Offset: {file_info_header.trace_chains_array_offset}")
        print(f"    Number of Trace Chains Entries: {file_info_header.num_trace_chains_entries}")
        print(f"    Filename Strings Offset: {file_info_header.filename_strings_offset}")
        print(f"    Filename Strings Size: {file_info_header.filename_strings_size}")
        print(f"    Volumes Information Offset: {file_info_header.volumes_info_offset}")
        print(f"    Number of Volumes: {file_info_header.num_volumes}")
        print(f"    Volumes Information Size: {file_info_header.volumes_info_size}")
        print(f"    Unknown1: 0x{file_info_header.unknown1:016x}")
        
        print("    Last Run Times:")
        for i, filetime in enumerate(file_info_header.last_run_times):
            print(f"        [{i}]: 0x{filetime:016x}")
        
        print(f"    Unknown2: 0x{file_info_header.unknown2:016x}")
        print(f"    Run Count: {file_info_header.run_count}")
        print(f"    Unknown3: {file_info_header.unknown3}")
        print(f"    Unknown4: {file_info_header.unknown4}")
        print(f"    Hash String Offset: {file_info_header.hash_string_offset}")
        print(f"    Hash String Size: {file_info_header.hash_string_size}")
        print(f"    Unknown5: {file_info_header.unknown5.hex()}")
        
        return file_info_header
    except ValueError as e:
        print(f"Error parsing file information header: {e}")
        return None

def read_volume_information_entries(uncompressed_data, file_info_header):
    """
    Read and display volume information entries from uncompressed prefetch data.
    
    Args:
        uncompressed_data (bytes): The uncompressed prefetch file data
        file_info_header: The parsed file information header
    """
    if file_info_header.num_volumes == 0:
        print("\nNo volume information entries found.")
        return []
    
    volumes = []
    volume_offset = file_info_header.volumes_info_offset
    
    print(f"\nVolume Information Entries ({file_info_header.num_volumes} volumes):")
    
    for i in range(file_info_header.num_volumes):
        try:
            volume_entry = parse_volume_information_entry(uncompressed_data, volume_offset)
            print(f"\n  Volume {i + 1}:")
            print(f"    Volume Device Path Offset: {volume_entry.volume_device_path_offset}")
            print(f"    Volume Device Path Num Chars: {volume_entry.volume_device_path_num_chars}")
            print(f"    Volume Creation Time: 0x{volume_entry.volume_creation_time:016x}")
            print(f"    Volume Serial Number: 0x{volume_entry.volume_serial_number:08x}")
            print(f"    File References Offset: {volume_entry.file_references_offset}")
            print(f"    File References Data Size: {volume_entry.file_references_data_size}")
            print(f"    Directory Strings Offset: {volume_entry.directory_strings_offset}")
            print(f"    Number of Directory Strings: {volume_entry.num_directory_strings}")
            print(f"    Unknown1: {volume_entry.unknown1}")
            print(f"    Unknown2: {volume_entry.unknown2.hex()}")
            print(f"    Unknown3: {volume_entry.unknown3}")
            print(f"    Unknown4: {volume_entry.unknown4.hex()}")
            print(f"    Unknown5: {volume_entry.unknown5}")
            
            if volume_entry.num_directory_strings > 0:
                directory_strings = read_directory_strings(uncompressed_data, volume_entry, file_info_header.volumes_info_offset)
                print(f"    Directory Strings ({len(directory_strings)}):")
                for j, s in enumerate(directory_strings):
                    print(f"        [{j}]: {repr(s)}")
            
            volumes.append(volume_entry)
            volume_offset += 96  # Each entry is 96 bytes
            
        except ValueError as e:
            print(f"Error parsing volume information entry {i + 1}: {e}")
            break
    
    return volumes

def read_directory_strings(uncompressed_data, volume_entry, volumes_info_offset):
    offset = volumes_info_offset + volume_entry.directory_strings_offset
    num_strings = volume_entry.num_directory_strings
    strings = []
    for i in range(num_strings):
        end = offset
        while end + 1 < len(uncompressed_data) and uncompressed_data[end:end+2] != b'\x00\x00':
            end += 2
        if end + 1 >= len(uncompressed_data):
            break
        string_bytes = uncompressed_data[offset:end]
        try:
            string = string_bytes.decode('utf-16-le')
        except UnicodeDecodeError:
            string = f"<decode error: {string_bytes.hex()}>"
        strings.append(string)
        offset = end + 2
    return strings

if __name__ == "__main__":
    read_mam_header(prefetch_file)
    uncompressed_prefetch_file, uncompressed_prefetch_file_header = MAM_to_SCCA(prefetch_file)
    if uncompressed_prefetch_file_header is not None:
        # uncompressed_prefetch_file_header = uncompressed_prefetch_file_header._replace(format_version=32)
        if uncompressed_prefetch_file_header.format_version != 31:
            logger.critical("Unsupported format version")
            print("this program only handles version 31")
            sys.exit(1)
        logger.info("Decompression and parsing successful")
        read_uncompressed_file_header(uncompressed_prefetch_file_header)
        if uncompressed_prefetch_file is not None:
            file_info = read_file_information_header(uncompressed_prefetch_file)
            if file_info is not None:
                read_volume_information_entries(uncompressed_prefetch_file, file_info)
    else:
        logger.critical("Decompression or parsing failed")
        print("Decompression or parsing failed")
        sys.exit(1)
import struct
from collections import namedtuple

# Define MAM file header structure using namedtuple for clean access
MAMHeader = namedtuple('MAMHeader', ['signature', 'uncompressed_size'])

def parse_mam_header(data):
    """
    Parse the MAM file header from binary data.
    
    Args:
        data (bytes): The binary content of the file
        
    Returns:
        MAMHeader: Namedtuple containing signature and uncompressed_size
        
    Raises:
        ValueError: If data is too short
    """
    if len(data) < 8:
        raise ValueError("Data too short for MAM header")
    
    signature, uncompressed_size = struct.unpack('<4sI', data[:8])
    return MAMHeader(signature, uncompressed_size)

# Define Uncompressed Prefetch Header structure
UncompressedPrefetchHeader = namedtuple('UncompressedPrefetchHeader', [
    'format_version', 'signature', 'unknown1', 'file_size', 
    'executable_filename', 'prefetch_hash', 'unknown_flags'
])

def parse_uncompressed_prefetch_header(data):
    """
    Parse the uncompressed prefetch file header from binary data.
    
    Args:
        data (bytes): The uncompressed prefetch file data
        
    Returns:
        UncompressedPrefetchHeader: Namedtuple containing header fields
        
    Raises:
        ValueError: If data is too short or invalid signature
    """
    if len(data) < 84:
        raise ValueError("Data too short for uncompressed prefetch header")
    
    # Unpack format_version (0-3), signature (4-7), unknown1 (8-11), file_size (12-15)
    format_version, signature, unknown1, file_size = struct.unpack('<I4sII', data[0:16])
    
    # Extract executable filename (16-75, 60 bytes, UTF-16 LE, null-terminated, padded with \x00)
    filename_bytes = data[16:76]
    executable_filename = filename_bytes.decode('utf-16-le').rstrip('\x00')
    
    # Unpack prefetch_hash (76-79), unknown_flags (80-83)
    prefetch_hash, unknown_flags = struct.unpack('<II', data[76:84])
    
    # Verify signature
    if signature != b'SCCA':
        raise ValueError(f"Invalid prefetch signature: {signature}")
    
    return UncompressedPrefetchHeader(
        format_version=format_version,
        signature=signature,
        unknown1=unknown1,
        file_size=file_size,
        executable_filename=executable_filename,
        prefetch_hash=prefetch_hash,
        unknown_flags=unknown_flags
    )

# Define File Information Header structure (version 30 - variant 2)
FileInformationHeader = namedtuple('FileInformationHeader', [
    'file_metrics_array_offset', 'num_file_metrics_entries',
    'trace_chains_array_offset', 'num_trace_chains_entries',
    'filename_strings_offset', 'filename_strings_size',
    'volumes_info_offset', 'num_volumes', 'volumes_info_size',
    'unknown1', 'last_run_times', 'unknown2',
    'run_count', 'unknown3', 'unknown4',
    'hash_string_offset', 'hash_string_size', 'unknown5'
])

def parse_file_information_header(data, offset=84):
    """
    Parse the file information header from binary data.
    
    Args:
        data (bytes): The uncompressed prefetch file data
        offset (int): Offset where the file information header starts (default: 84)
        
    Returns:
        FileInformationHeader: Namedtuple containing header fields
        
    Raises:
        ValueError: If data is too short
    """
    if len(data) < offset + 212:
        raise ValueError("Data too short for file information header")
    
    # Extract data starting from the offset
    header_data = data[offset:offset + 212]
    
    # Unpack the fields according to the specification
    file_metrics_array_offset = struct.unpack('<I', header_data[0:4])[0]
    num_file_metrics_entries = struct.unpack('<I', header_data[4:8])[0]
    trace_chains_array_offset = struct.unpack('<I', header_data[8:12])[0]
    num_trace_chains_entries = struct.unpack('<I', header_data[12:16])[0]
    filename_strings_offset = struct.unpack('<I', header_data[16:20])[0]
    filename_strings_size = struct.unpack('<I', header_data[20:24])[0]
    volumes_info_offset = struct.unpack('<I', header_data[24:28])[0]
    num_volumes = struct.unpack('<I', header_data[28:32])[0]
    volumes_info_size = struct.unpack('<I', header_data[32:36])[0]
    unknown1 = struct.unpack('<Q', header_data[36:44])[0]
    
    # Last run times - 8 FILETIMEs (each 8 bytes)
    last_run_times = []
    for i in range(8):
        start = 44 + (i * 8)
        end = start + 8
        filetime = struct.unpack('<Q', header_data[start:end])[0]
        last_run_times.append(filetime)
    
    unknown2 = struct.unpack('<Q', header_data[108:116])[0]
    run_count = struct.unpack('<I', header_data[116:120])[0]
    unknown3 = struct.unpack('<I', header_data[120:124])[0]
    unknown4 = struct.unpack('<I', header_data[124:128])[0]
    hash_string_offset = struct.unpack('<I', header_data[128:132])[0]
    hash_string_size = struct.unpack('<I', header_data[132:136])[0]
    unknown5 = header_data[136:212]  # 76 bytes of unknown data
    
    return FileInformationHeader(
        file_metrics_array_offset=file_metrics_array_offset,
        num_file_metrics_entries=num_file_metrics_entries,
        trace_chains_array_offset=trace_chains_array_offset,
        num_trace_chains_entries=num_trace_chains_entries,
        filename_strings_offset=filename_strings_offset,
        filename_strings_size=filename_strings_size,
        volumes_info_offset=volumes_info_offset,
        num_volumes=num_volumes,
        volumes_info_size=volumes_info_size,
        unknown1=unknown1,
        last_run_times=last_run_times,
        unknown2=unknown2,
        run_count=run_count,
        unknown3=unknown3,
        unknown4=unknown4,
        hash_string_offset=hash_string_offset,
        hash_string_size=hash_string_size,
        unknown5=unknown5
    )

# Define Volume Information Entry structure (version 30)
VolumeInformationEntry = namedtuple('VolumeInformationEntry', [
    'volume_device_path_offset', 'volume_device_path_num_chars',
    'volume_creation_time', 'volume_serial_number',
    'file_references_offset', 'file_references_data_size',
    'directory_strings_offset', 'num_directory_strings',
    'unknown1', 'unknown2', 'unknown3', 'unknown4', 'unknown5'
])

def parse_volume_information_entry(data, offset=0):
    """
    Parse a volume information entry from binary data.
    
    Args:
        data (bytes): The binary data containing the volume information entry
        offset (int): Offset where the volume information entry starts (default: 0)
        
    Returns:
        VolumeInformationEntry: Namedtuple containing volume information fields
        
    Raises:
        ValueError: If data is too short
    """
    if len(data) < offset + 96:
        raise ValueError("Data too short for volume information entry")
    
    # Extract data starting from the offset
    entry_data = data[offset:offset + 96]
    
    # Unpack the fields according to the specification
    volume_device_path_offset = struct.unpack('<I', entry_data[0:4])[0]
    volume_device_path_num_chars = struct.unpack('<I', entry_data[4:8])[0]
    volume_creation_time = struct.unpack('<Q', entry_data[8:16])[0]
    volume_serial_number = struct.unpack('<I', entry_data[16:20])[0]
    file_references_offset = struct.unpack('<I', entry_data[20:24])[0]
    file_references_data_size = struct.unpack('<I', entry_data[24:28])[0]
    directory_strings_offset = struct.unpack('<I', entry_data[28:32])[0]
    num_directory_strings = struct.unpack('<I', entry_data[32:36])[0]
    unknown1 = struct.unpack('<I', entry_data[36:40])[0]
    unknown2 = entry_data[40:64]  # 24 bytes of unknown data
    unknown3 = struct.unpack('<I', entry_data[64:68])[0]
    unknown4 = entry_data[68:92]  # 24 bytes of unknown data
    unknown5 = struct.unpack('<I', entry_data[92:96])[0]
    
    return VolumeInformationEntry(
        volume_device_path_offset=volume_device_path_offset,
        volume_device_path_num_chars=volume_device_path_num_chars,
        volume_creation_time=volume_creation_time,
        volume_serial_number=volume_serial_number,
        file_references_offset=file_references_offset,
        file_references_data_size=file_references_data_size,
        directory_strings_offset=directory_strings_offset,
        num_directory_strings=num_directory_strings,
        unknown1=unknown1,
        unknown2=unknown2,
        unknown3=unknown3,
        unknown4=unknown4,
        unknown5=unknown5
    )
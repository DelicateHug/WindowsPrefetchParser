import ctypes
import struct
import sys
from collections import namedtuple
from logger import logger

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

def decompress_xpress_huff(content):
    """
    Decompress Xpress Huff compressed prefetch file data using ntdll.dll's RtlDecompressBufferEx.
    
    Args:
        content (bytes): The full binary content of the prefetch file.
    
    Returns:
        tuple: (MAMHeader, bytes, UncompressedPrefetchHeader) on success, None on failure.
    """
    try:
        # Parse the MAM file header
        mam_header = parse_mam_header(content)
        
        # Verify signature
        if mam_header.signature != b'MAM\x04':
            print("Invalid MAM file signature")
            return None
        
        compressed = content[8:]
        compressed_size = len(compressed)
        expected_size = mam_header.uncompressed_size
        
        # Load ntdll.dll
        ntdll = ctypes.windll.ntdll
        
        # Define function pointers
        RtlGetCompressionWorkSpaceSize = ntdll.RtlGetCompressionWorkSpaceSize
        RtlGetCompressionWorkSpaceSize.argtypes = [
            ctypes.c_ushort,  # CompressionFormat
            ctypes.POINTER(ctypes.c_ulong),  # CompressBufferWorkSpaceSize
            ctypes.POINTER(ctypes.c_ulong)   # CompressFragmentWorkSpaceSize
        ]
        RtlGetCompressionWorkSpaceSize.restype = ctypes.c_long
        
        RtlDecompressBufferEx = ntdll.RtlDecompressBufferEx
        RtlDecompressBufferEx.argtypes = [
            ctypes.c_ushort,  # CompressionFormat
            ctypes.c_void_p,  # UncompressedBuffer
            ctypes.c_ulong,   # UncompressedBufferSize
            ctypes.c_void_p,  # CompressedBuffer
            ctypes.c_ulong,   # CompressedBufferSize
            ctypes.POINTER(ctypes.c_ulong),  # FinalUncompressedSize
            ctypes.c_void_p   # WorkSpace
        ]
        RtlDecompressBufferEx.restype = ctypes.c_long
        
        # Constants
        COMPRESSION_FORMAT_XPRESS_HUFF = 4
        COMPRESSION_ENGINE_STANDARD = 0
        format = COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_STANDARD
        
        # Get workspace size
        workspace_size = ctypes.c_ulong()
        fragment_workspace_size = ctypes.c_ulong()
        status = RtlGetCompressionWorkSpaceSize(format, ctypes.byref(workspace_size), ctypes.byref(fragment_workspace_size))
        if status != 0:
            raise Exception(f"RtlGetCompressionWorkSpaceSize failed: {status}")
        
        # Allocate workspace
        workspace = None
        if workspace_size.value > 0:
            workspace = ctypes.create_string_buffer(workspace_size.value)
        
        # Allocate buffer for uncompressed data
        uncompressed = bytearray(expected_size)
        uncompressed_buffer = (ctypes.c_ubyte * expected_size).from_buffer(uncompressed)
        
        compressed_buffer = (ctypes.c_ubyte * compressed_size)(*compressed)
        
        final_size = ctypes.c_ulong()
        
        # Decompress
        status = RtlDecompressBufferEx(
            format,
            ctypes.cast(uncompressed_buffer, ctypes.c_void_p),
            expected_size,
            ctypes.cast(compressed_buffer, ctypes.c_void_p),
            compressed_size,
            ctypes.byref(final_size),
            workspace
        )
        
        if status == 0:
            # Parse the uncompressed prefetch header
            try:
                prefetch_header = parse_uncompressed_prefetch_header(bytes(uncompressed))
                return mam_header, bytes(uncompressed), prefetch_header
            except ValueError as e:
                print(f"Failed to parse prefetch header: {e}")
                return None
        else:
            return None
    
    except Exception as e:
        print(f"Decompression error: {e}")
        logger.error(f"Decompression error: {e}")
        return None
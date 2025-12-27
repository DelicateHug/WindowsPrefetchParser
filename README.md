# WindowsPrefetchParser

## Overview

WindowsPrefetchParser is an educational Python program designed to parse Windows prefetch files, specifically focusing on version 31. This project is not intended to be a high-performance or comprehensive prefetch parser, but rather a learning tool to demonstrate fundamental concepts in binary file parsing—a common task in Windows system analysis and forensics.

## Educational Purpose

The primary goal of this program is **education**. It serves as a practical example for understanding:

- How to read and parse binary file formats
- Working with structured data in Windows systems
- Decompression techniques (Xpress Huffman)
- Handling complex binary structures with offsets and variable-length data
- Python's `struct` module for binary unpacking
- Named tuples for clean data representation

While prefetch files are the subject matter, the real value lies in learning these binary parsing techniques, which are applicable to many other Windows artifacts like registry hives, event logs, and other system files.

## Features

- Parses Windows prefetch files in MAM (compressed) format
- Decompresses Xpress Huffman compressed data to SCCA format
- Extracts and displays key information from prefetch headers
- Handles file information headers, volume information, and directory strings
- Supports only version 31 prefetch files (by design for simplicity)
- Includes detailed logging and error handling
- Modular code structure for easy understanding

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Usage

1. Clone or download the repository
2. Run the parser with a prefetch file:

```bash
python main.py <path_to_prefetch_file>
```

For example, using the included sample file:

```bash
python main.py AM_DELTA_PATCH_1.443.326.0.EX-8B3BB46B.pf
```

The program will output parsed information including:
- MAM header details
- Uncompressed file header
- File information header
- Volume information entries
- Directory strings

## File Structure

- `main.py` - Main entry point and parsing logic
- `decompress.py` - Xpress Huffman decompression implementation
- `structs.py` - Data structure definitions and parsing functions
- `logger.py` - Logging configuration
- `README.md` - This file
- `AM_DELTA_PATCH_1.443.326.0.EX-8B3BB46B.pf` - Sample prefetch file for testing

## How It Works

1. **MAM Header Parsing**: Reads the 8-byte compressed file header
2. **Decompression**: Uses Xpress Huffman algorithm to decompress MAM to SCCA format
3. **Header Validation**: Verifies the SCCA signature and version (must be 31)
4. **Structured Parsing**: Uses `struct.unpack` to parse binary data into named tuples
5. **Offset-based Reading**: Follows offsets to read variable-length data sections
6. **String Extraction**: Handles UTF-16 LE encoded strings with null termination

## Limitations

- Only supports prefetch version 31
- Not optimized for performance
- Does not parse all possible prefetch data sections (file metrics, trace chains, etc.)
- Educational focus means some production features are omitted

## Learning Outcomes

By studying this code, you'll learn:

- Binary file format analysis
- Endianness handling (little-endian)
- Offset-based data structures
- Decompression algorithms
- Error handling in binary parsing
- Modular code organization for complex parsers

## Contributing

This is primarily an educational project. Contributions that enhance the learning value or add educational comments are welcome.

## License

This project is for educational purposes. Use at your own discretion.
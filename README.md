# PeePDF Service

This Assemblyline service uses the Python PeePDF library against PDF files. 

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

The PeePDF service will report the following information for each file when present:

####PDF File Information

- MD5
- SHA1
- SHA256
- Size
- Version
- Binary (T|F)
- Linearized  (T|F)
- Encryption Algorithms
- Updates 
- Objects 
- Streams 
- Versions Info:
    - Catalog
    - Info
    - Objects
    - Streams
    - Xref streams
    - Compressed Objects
    - Encoded
    - Objects with JS code

####Heuristics

**PeePDF.1**: Embedded PDF in XDP.

**PeePDF.2**: A buffer was found in the javascript code.

**PeePDF.3**: The eval() function is found in the javascript block. 

**PeePDF.4**: The unescape() function is found in the javascript block. 

**PeePDF.5**: Possible Javascript Shellcode.

**PeePDF.6**: Unescaped Javascript Buffer.

**PeePDF.7**: Suspicious Javascript.

####Other Items of Interest

- CVE identifiers
- Embedded files (will attempt to extract)
- Javascript (will attempt to extract)
- URL detection
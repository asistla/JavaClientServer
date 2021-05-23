Simulates simple UDP transmission and reception with basic data integrity check using RC4 checksum.
Uses port 9696 by default. If you want to change this, do it in both the transmission and reception classes, or it obviously won't work.
At the moment can send specific byte arrays. I might add stuff to make it send real files and such, but that's trivial from here. The problem is receiving in file format, something I intend to look into, but not right now.

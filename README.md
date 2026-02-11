This repository contains the source codes for the paper.

## Language Used for code
1.  C-language
2.  Python

## Setup
1.  To install gcc, use the following command:
	    * `sudo apt update`
	    * `sudo apt install build-essential`
2.  To install python kernel, use the following command:
        * `sudo apt update`      
	    * `sudo apt install python3`
	    
## File Structure
1.  `ascon_ilp.py`: Script for finding minimal number of fault location for Ascon using ILP.
2.  `aradi_ilp.py`: Script for finding minimal number of fault location for Aradi using ILP.

## For Ascon
1.  `offlinephase.c`			: Script for constructing offline phase table.
2.  `onlinephase_decryption.c` 	: Script for constructing online phase table using decryption oracle.
3.  `onlinephase_encryption.c`	: Script for constructing online phase table using encryption oracle.
4.  `masterkey_recovery.c`		: Script to recover masterkey of Ascon using precomputation table and online phase table.

## For Aradi
1.  `function_encryption.h` and `function_decryption.h`	: Script for writing necessary functions for encryption and decryption of Aradi.
2.  `onlinephase_encryption_subkey_recovery.c` 			: Script for recover subkeys of Aradi using encryption oracle.
4.  `onlinephase_decryption_masterkey_recovery.c`		: Script for recover masterkey of Aradi using decryption oracle.

## Usage

## For file_name.py file:
1.  compile and run the programme:`python3 file_name.py`

## For file_name.c file:
1.  compile the programme	:`gcc file_name.c`
2.  run the file			:`./a.out`

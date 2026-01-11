This repository contains the source codes for the paper, '**{Some Results on the Aegis Family of ciphers} **'.

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

1.  `ascon_ilp.py`:
2.  `aradi_ilp.py`:

## For Ascon
1.  `offlinephase.c`:
2.  `onlinephase_decryption.c`:
3.  `onlinephase_encryption.c`:
4.  `masterkey_recovery.c`:

## For Aradi
1.  `function_encryption.h` and `function_decryption.h`: Script for writing necessary functions for encryption and decryption of Aradi.
2.  `onlinephase_encryption_subkey_recovery.c`: Script for writing necessary functions for encryption and decryption of toy version of Aradi.
3.  `onlinephase_decryption_masterkey_recovery.c`: Script to find the average number of survival keys when the pair is a right pair.

## Usage

## For ***.py file:
1.  compile and run the programme: `python3 file_name.py`

## For ***.c file:
1.  compile the programme:  `gcc file_name.c`
2.  run the file:           `./a.out`

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
1.  `pulp_ascon_optimizer.py`and `pulp_aradi_optimizer.py`      : Script for finding minimal number of fault location for Ascon and Aradi using ILP using Pulp.
2.  `gurobi_ascon_optimizer.py`and `gurobi_aradi_optimizer.py`  : Script for finding minimal number of fault location for Ascon and Aradi using ILP using Gurobi.

## For Ascon
1.  `ascon_half_keyrecovery_decryption.c` 	: Script for recover half of the masterkey using decryption oracle.
2.  `simulate_ascon_decryption.c`	        : Script for count average number faulty query to recover half of the masterkey using decryption oracle.
3.  `ascon_full_keyrecovery_encryption.c`	: Script to recover full masterkey using encryption oracle.

## For Aradi
1.  `function_decryption.h`								: Script for writing necessary functions for encryption and decryption of Aradi.
2.  `aradi_fullkey_recovery_randomfault.c` 				: Script for recover key with random fault model.
3.  `aradi_fullkey_recovery_deterministicfault.c`		: Script for recover key with determinitic fault model.
4.  `simulate_aradi_singlerow_1.c'						: Script for count average number random faults, distinct faults and used faults for full coverage for the subkey sk^0.
5.  `simulate_aradi_singlerow_1.c'						: Script for count average number random faults, distinct faults and used faults for full coverage for the subkey sk^1. 

## Usage

## For file_name.py file:
1.  compile and run the programme:`python3 file_name.py`

## For file_name.c file:
1.  compile the programme	:`gcc file_name.c`
2.  run the file			:`./a.out`

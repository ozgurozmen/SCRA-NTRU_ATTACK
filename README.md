## Description

Universal forgery attack to the NTRU instantiation of Structure-free Compact Rapid Authentication (SCRA) scheme published in IEEE TIFS 2017 (https://ieeexplore.ieee.org/abstract/document/7953565/). 

## Usage 

1. Install b2 library found in https://github.com/BLAKE2/libb2

2. Go to the SCRA_pqNTRUATTACK folder, update the paths in the makefile and make. Run the executable generated under Debug folder. This will generate three text files. Then, go to the Matlab script (Attack.m) and run it. This will first generate a row echelon matrix and then forge signatures on random messages.

Note: I highly recommend using CodeLite to run the SCRA_pqNTRUATTACK workspace (http://codelite.org).

## License

This code is implemented on top of the base implementation of pqNTRUsign (https://github.com/zhenfeizhang/pqNTRUSign)

Please check the licenses for the dependencies before using this code.

## Contact

Please contact me (ozmenmu@oregonstate.edu) for any questions

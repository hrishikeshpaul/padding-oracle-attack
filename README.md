# CBC Padding Oracle Attack

his paper demonstrates a real world vulnerability in the AES-Cipher 
Block Chaining method of encryption and decryption known as Padding 
Oracle Attack. By analyzing the boolean output from the server - 
whether or not a message has the correct padding, we were able to 
decipher the cipher text as well and encrypt a plain text. 
This paper discusses the problem with CBC methods, the way 
in which the attack was formulated and analyzes the complexity 
of the attacks.

## How to run

1. Start the server

   ```shell script
   $ ./aes-cbc-padding-oracle-server
   ```

2. Run the code and selection the option

   ```
   $ python3 oracle.py
   ```
# HybridEncryption1

SELECTED CHALLENGE
Hybrid Encryption I
INTRODUCTION
The hybrid communication system implemented aims to use the advantages of both symmetric and asymmetric encryption. A random key (K) is generated for symmetric encryption. This session key is used to encrypt the given plaintext via AES 128 bit encryption. Finally, the session key is encrypted using RSA plain form implementation(Asymmetric encryption) to forward it to the recipient.

AIM

● Implement the hybrid system

● Break the hybrid system

Our implementation is made up of two crypto systems: AES and RSA.

An instance of KeyGenerator is used to generate a 128-bit session key for AES [generateKey()]. The obtained SecretKey instance is displayed in its hex representation by means of encoding the SecretKey as a hex string for our convenience.

Now that the session key is in place, our program accepts the plaintext message to be encrypted from the user via the command line. This message could be of any length.

Once the plaintext message has been accepted, it needs to be encrypted. For this system, the message is encrypted through a combination of AES and ECB algorithms. The encrypt method first sets the appropriate modes and key to a Cipher instance. The message is then converted from a string format into a bytes array, and is then passed to the initialized Cipher model’s doFinal() in ENCRYPT mode, which in turn returns the ciphertext as a bytes array using base64 encoding. For better comprehension, we have displayed this ciphertext as a hex string.



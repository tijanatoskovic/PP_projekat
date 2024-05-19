# EnDecrypter
In the current era, unauthorized attacks on computer systems and data theft are becoming more frequent. That is why it is extremely important to keep files that are important to us in a protected form (encrypted). EnDecrypter is an application that serves for encryption and decryption with the help of two well-known algorithms AES and RSA.

## Installation
+ Download and install required programming language and gui framework:
  - Download and install [GO](https://go.dev/doc/install)
  - Download and install [Fyne.io](https://docs.fyne.io/started/)
+ To run the program:
  ```
  go run .
  ```
## Usage
EnDecrypter allows you to encrypt and decrypt files (such as text files, images, etc.) using AES and RSA algorithms. Here’s how you can use the application:

1. **Select a File**: Choose a file from your computer that you want to encrypt or decrypt.
2. **Choose Action**: Select whether you want to encrypt or decrypt the file.
3. **Select Algorithm**: Choose between AES or RSA for the encryption/decryption process.
   + **For AES Algorithm**:
     - A new window will appear prompting you to enter and confirm a password.
     - Click on the "Submit" button after entering the password.
     
   + **For RSA Algorithm**:
     - The application will use the RSA keys generated for the encryption/decryption process.
4. **Execute Action**: Click on the "Encrypt/Decrypt" button to perform the desired action.
5. **Help**: Click the "Help!" button for a detailed description of how to use the program
6. **Exit**: You can close the application by pressing `Ctrl+W`.

> **Important Note**: You cannot decrypt a file that has not been previously encrypted using our application.

## How AES and RSA Algorithms Work

### AES (Advanced Encryption Standard)
AES is a symmetric encryption algorithm, which means the same key is used for both encryption and decryption. It operates on fixed block sizes (128 bits) and supports key sizes of 128, 192, or 256 bits. The encryption process involves several rounds of substitution, permutation, and mixing of the input data to produce the ciphertext. AES is widely used due to its efficiency and strong security.

### RSA (Rivest-Shamir-Adleman)
RSA is an asymmetric encryption algorithm, utilizing a pair of keys: a public key for encryption and a private key for decryption. The security of RSA is based on the difficulty of factoring large prime numbers. The algorithm involves generating two large prime numbers, calculating their product (which forms the modulus), and using this modulus along with a public exponent to encrypt the data. The private key, derived from the same prime numbers, is used to decrypt the data.

## Program Paradigms
+ **Students:** Tijana Tošković, Luka Đekić
+ **Teaching Assistant:** Marija Marković
+ **Professor:** prof. dr Milena Vujošević Janičić
  
## Gallery:
![pp](https://github.com/tijanatoskovic/PP_projekat/assets/155033071/88ef654e-0b6d-4019-b174-7602646ba173)


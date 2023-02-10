import { Cipher, getRandomValues } from 'crypto';
import SEAL from 'node-seal';
import { CipherText } from 'node-seal/implementation/cipher-text';
import { PlainText } from 'node-seal/implementation/plain-text';
import { SEALLibrary } from 'node-seal/implementation/seal';
import { randomBytes } from "crypto"
import { decode } from 'punycode';

async function main() {
    // ES6 or CommonJS
    // import SEAL from 'node-seal'
    // const SEAL = require('node-seal')
  
    // Using CommonJS for RunKit
    // const SEAL = require('node-seal')
    const seal = await SEAL()
    const schemeType = seal.SchemeType.bfv
    const securityLevel = seal.SecurityLevel.tc128
    const polyModulusDegree = 8192
    const bitSizes = [36, 36, 37, 38, 39]
    const bitSize = 20
  
    const parms = seal.EncryptionParameters(schemeType)
  
    // Set the PolyModulusDegree
    parms.setPolyModulusDegree(polyModulusDegree)
  
    // Create a suitable set of CoeffModulus primes
    parms.setCoeffModulus(
      seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    )
  
    // Set the PlainModulus to a prime of bitSize 20.
    parms.setPlainModulus(
      seal.PlainModulus.Batching(polyModulusDegree, bitSize)
    )
  
    const context = seal.Context(
      parms, // Encryption Parameters
      true, // ExpandModChain
      securityLevel // Enforce a security level
    )
  
    if (!context.parametersSet()) {
      throw new Error(
        'Could not set the parameters in the given context. Please try different encryption parameters.'
      )
    }
  
    const encoder = seal.BatchEncoder(context)
    const keyGenerator = seal.KeyGenerator(context)
    const publicKey_receiver = keyGenerator.createPublicKey()
    const secretKey_receiver = keyGenerator.secretKey()
    const encryptor = seal.Encryptor(context, publicKey_receiver)
    const decryptor = seal.Decryptor(context, secretKey_receiver)
    const evaluator = seal.Evaluator(context)
  
    // RECEIVER

    // Receiver set
    const set_receiver = Int32Array.from([1, 2, 3, 4, 5])
    const set_receiver_length = set_receiver.length
  
    // Encode receiver set
    const setPlaintext_receiver = encoder.encode(set_receiver) as PlainText
  
    // Encrypt the each element in the receiver set
    // This is sent to the sender
    const setCiphertext_receiver = encryptor.encrypt(setPlaintext_receiver) as CipherText
  
    // SENDER
    
    // Sender set
    const set_sender = Int32Array.from([2, 3, 7])

    // Generate random (non-zero) plaintexts
    const randomPlaintext_sender = new Int32Array(set_receiver.length)
    for (let i=0; i < set_receiver.length; i++) {
      randomPlaintext_sender[i] = randomBytes(32).readUInt32BE();
    }
    const randomPlaintext_sender_encoded = encoder.encode(randomPlaintext_sender) as PlainText

    const result_sender = seal.CipherText();
    const firstValue = Int32Array.from(Array(set_receiver_length).fill(set_sender[0]))
    const firstValue_encoded = encoder.encode(firstValue) as PlainText

    evaluator.subPlain(setCiphertext_receiver, firstValue_encoded, result_sender);

    for (let i=1; i < set_sender.length; i++) {
      const iThValue = Int32Array.from(Array(set_receiver.length).fill(set_sender[i]))
      const iThValue_encoded = encoder.encode(iThValue) as PlainText
      const temp = seal.CipherText()
      evaluator.subPlain(setCiphertext_receiver, iThValue_encoded, temp);
      evaluator.multiply(result_sender, temp, result_sender);
    }
    
    evaluator.multiplyPlain(result_sender, randomPlaintext_sender_encoded, result_sender);

    const decrypted = decryptor.decrypt(result_sender) as PlainText
    const decoded = encoder.decode(decrypted)
    console.log(decoded)

    return
}

main();
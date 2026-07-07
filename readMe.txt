1. Message
2. SignedMessage = Message + Signature
3. Compress(SignedMessage)
4.1. Generate Ks
4.2. Encrypt CompressedMessage(KS)
4.3. Encypt KS (receiverPU)
4.4. EncyptedMessage = EncryptedKS+ EncryptedMessage
5. Radix64 (EncryptedMessage)
6. RadixMessage + EncodeOptions
7. Split

Message:

(EncryptedKS + (Message + Signature)) + Options






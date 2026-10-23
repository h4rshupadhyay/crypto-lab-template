**Subject: Information Security Lab (ICT 3141)**  
**Lab End-Sem Practice Examination: 20 Marks | Duration: 90 minutes**

**SECURE HOSPITAL BILLING AND EXPENDITURE ANALYSIS SYSTEM**

**Scenario**

A hospital receives treatment bills from three departments: **Cardiology, Neurology, and Orthopaedics**. Its central server must verify submitted bills and calculate department-wise expenditure without learning individual bill amounts.

Develop a **menu-driven Python program** implementing the following client, server, and accounts-authority functions.

**Client-side requirements**

An authenticated billing officer enters a bill ID, patient ID, department ID, and a positive, whole-number amount in rupees.

1. Encrypt the amount using the **Paillier public key** belonging to the accounts authority.
    
2. Create a record containing the bill ID, patient ID, department ID, and Paillier-encrypted amount. **Do not include the plaintext amount in this record.**
    
3. Compute a **SHA-256 hash** of the serialized record.
    
4. Encrypt the record using **AES-128-CBC**, with a fresh random session key and IV for every submission.
    
5. Encrypt the AES session key using the hospital server’s **ElGamal public key**. Use a reversible encoding that preserves the complete 16-byte AES key, including leading zero bytes.
    
6. Generate a **Schnorr digital signature** over a package containing the record hash, AES ciphertext, IV, ElGamal-encrypted session key, and bill ID.
    
7. Obtain a signed timestamp token from a trusted timestamp-authority module. The token must bind the submission time to the signed package.
    
8. Submit the encrypted package, signature, and timestamp token.
    

For this laboratory exercise, the timestamp authority may be simulated locally using its own signing key and a trusted public key registered with the server.

**Server-side requirements**

The authenticated hospital server must:

1. Verify the billing officer’s Schnorr signature using a previously registered public key.
    
2. Verify the timestamp authority’s signature and confirm that the submission falls within the configured billing period.
    
3. Recover the AES session key using its **ElGamal private key**.
    
4. Decrypt the AES record, recompute its SHA-256 hash, and compare it with the signed hash.
    
5. Reject duplicate bill IDs, invalid signatures, altered records, and submissions outside the billing period.
    
6. Store accepted records while retaining individual amounts as **Paillier ciphertexts**.
    
7. Maintain a **searchable encryption index** supporting searches by patient ID or department ID. Searches must return matching bill IDs without decrypting bill amounts.
    
8. Homomorphically aggregate accepted bill amounts department-wise, without decrypting individual amounts.
    

Use a consistent search-token construction. Independently randomized encryptions of the same keyword must not be assumed to produce matching ciphertexts.

**Accounts-authority requirements**

The authenticated accounts authority must:

1. View the number of accepted bills included in each department’s aggregate.
    
2. Decrypt the final department-wise aggregate using the **Paillier private key**.
    
3. Display the total expenditure for each department.
    
4. Reject requests to decrypt an individual bill through the application interface.
    

The hospital server must not possess the Paillier private key. This exercise requires role-restricted aggregate decryption; implementing cryptographic threshold decryption is not required.

**Task**

Write a menu-driven Python program implementing all the specified functions.

- Enforce authentication and role-based access control.
    
- Use dictionaries, lists, files, or a database to store encrypted records, signatures, hashes, timestamp tokens, and verification status.
    
- Keep private keys separate from ordinary stored records.
    
- Aggregate each accepted bill only once.
    
- Display the cryptographic outputs and verification results clearly.
    
- Provide a tampering demonstration showing that modification of a submitted package causes rejection.
    

Client and server roles may be implemented as separate functions in one program. Socket programming is optional.

**Mandatory menus**

```
MAIN MENU
1. Billing Officer
2. Hospital Server
3. Accounts Authority
4. Exit

BILLING OFFICER MENU
1. Create and submit bill
2. View submission status
3. Back

HOSPITAL SERVER MENU
1. Verify submitted bill
2. Search by patient ID
3. Search by department ID
4. Aggregate accepted bills
5. Demonstrate tampering detection
6. Back

ACCOUNTS AUTHORITY MENU
1. View aggregate details
2. Decrypt department total
3. Back
```

**Illustrative input–output**

Cryptographic values below are placeholders. Your program must compute and display actual values.

```
Login: Billing Officer

Bill ID: B001
Patient ID: P101
Department ID: 1
Amount: 2500

Paillier-encrypted amount: <ciphertext>
SHA-256 record hash: <hex digest>
AES IV: <hex value>
AES-128-CBC ciphertext: <hex value>
ElGamal-encrypted AES key: <c1, c2>
Schnorr signature: <signature values>
Signed timestamp token: <token>
B001 submitted successfully.

Bill ID: B002
Patient ID: P102
Department ID: 1
Amount: 3500

B002 submitted successfully.
```

```
Login: Hospital Server
Verify bill: B001

Schnorr signature: VALID
Timestamp token: VALID
Submission within billing period: YES
ElGamal session-key recovery: SUCCESS
AES record decryption: SUCCESS
SHA-256 comparison: MATCH
B001 accepted. Bill amount remains Paillier-encrypted.

Verify bill: B002
B002 accepted.

Search department: 1
Matching bill IDs: B001, B002

Aggregate department: 1
Accepted bills included: 2
Aggregate ciphertext: C = C_B001 × C_B002 mod n²
Individual amounts were not decrypted.
```

```
Login: Accounts Authority
Decrypt department total: 1

Department: Cardiology
Number of bills: 2
Total expenditure: Rs. 6000
```

```
Tampering demonstration:
Modify one byte of a submitted AES ciphertext.

Verification result: INVALID SIGNATURE
Submission rejected.
```

**Evaluation scheme**

|Write-up|Marks|
|---|---|
|System flow, role menus, and access control|1|
|AES and ElGamal encryption procedures|1|
|SHA-256 and Schnorr signature procedures|1|
|Paillier aggregation and aggregate decryption|1|
|Timestamp validation, searchable index, and storage|1|
|**Total**|**5**|

**Execution: 15 marks, one mark each**

1. Bill entry and input validation.
    
2. Paillier encryption of individual amounts.
    
3. SHA-256 hashing.
    
4. AES-128-CBC encryption.
    
5. ElGamal encryption of the AES key.
    
6. Schnorr signature generation.
    
7. Signed timestamp-token generation.
    
8. Signature and timestamp verification.
    
9. Session-key recovery and AES decryption.
    
10. Hash comparison and tampering rejection.
    
11. Duplicate-bill rejection.
    
12. Search by patient and department.
    
13. Homomorphic aggregation.
    
14. Authorized aggregate decryption.
    
15. Complete menu-driven execution with role-based access control.
    

**Note:** If the program is not menu-driven, the total marks obtained will be reduced to half.
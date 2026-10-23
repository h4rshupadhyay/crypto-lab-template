# Open-code exam template

Run the program directly:

```bash
python3 expense_reporting_system.py
```

Dependencies: `python3 -m pip install pycryptodome cryptography`.

The file uses a procedural layout: settings, file handling, crypto
functions, client/server workflows, encrypted search, totals, and a shared menu.
There is no application class, command-line parser or login step.

## What to edit

- `DATA_DIR`: folder containing saved keys and records.
- `CONFIG`: algorithms, key sizes, modes, hash and numeric operation.
- `SCENARIO`: field labels, groups, voting choices and release mode.
- `EMPLOYEES`: registered employee/officer IDs; each has a signing key.
- `TRUSTEES`: the three trustee IDs for 2-of-3 release.
- `PERMISSIONS`: role names and allowed actions. Changing a role's action set
  changes both its menu and its access to operations.
- `role_menu()`: shared menu labels and ordinary `if/elif` action handling.

## Default expense reporting workflow

1. Choose **Voter**, select `employee1`, then choose **Submit record**. Enter
   department `1` and an amount. Voter is the record-submitter role.
   The program prints the record, hash, session key and IV/nonce in hex,
   ciphertext, wrapped key, signature, signed timestamp and transaction ID.
2. Choose **Auditor → Verify submissions**. Enter that transaction ID,
   or leave it blank to verify all pending submissions. Only accepted records
   contribute to **Encrypted totals** and auditor searches.
3. Choose **Auditor** to search by group, employee/subject, or UTC time range.
   The amounts remain encrypted under Paillier.
4. Once submissions are verified, choose **Coordinator → Close collection**.
5. Choose **Trustee → Generate partial decryption** for `trustee1` and `trustee3`
   (any two distinct trustees work), then choose **Coordinator → Publish totals**.

Role selection simulates access permissions without passwords. Operation
functions check the selected role's permissions. Submitters select an account
before entering their menu; **View own receipts** lists only that account's
transaction IDs, statuses and signed timestamps. Files and all roles share one
Python process. Trustee partial decryptions still require registered trustee keys.

For example, adding `view_encrypted_totals` to `PERMISSIONS['auditor']` makes
**Encrypted totals** available to auditors. Removing an action hides its menu
option and makes calls to the corresponding operation fail with permission denied.

The default algorithms are AES-128-CBC, RSA-2048-OAEP wrapping, SHA-256, Schnorr,
Paillier addition and a separately signed, package-bound TSA timestamp.
The timestamp and package signature are checked before record decryption.
During server verification, the console also shows the recovered session key,
decrypted record, received/recomputed hashes and verification results. Session
keys are printed for the lab demonstration; they are not added to saved records.
Hashes and signature values are displayed in hexadecimal, including TSA and
trustee signatures. Saved signature formats are unchanged.

## Adapt to other questions

| Scenario | Settings to change |
|---|---|
| Donation/bill totals | `choices=[]`, `operation='sum'` |
| Voting | `choices=['Alice', 'Bob']`, `operation='count'`, `one_per_subject=True` |
| Average scores | `choices=[]`, `operation='average'` |
| Public weighted totals | `choices=[]`, `operation='weighted_sum'` |
| Encrypted products | `homomorphic='rsa'` or `'elgamal'`, `operation='product'`, `threshold=False` |
| Hospital officer entering patient IDs | `subject_is_user=False`, rename labels/groups, `threshold=False` if one authority is specified |

Voting encrypts a 0/1 vector and counts each candidate separately. Averages
release a sum divided by the accepted record count. Weighted totals use public
integer weights. In single-authority mode, use **Coordinator → Publish totals** after
closure; partial decryptions are unnecessary.

Symmetric options are AES/DES/3DES; wrapping options are RSA/ElGamal/Rabin/ECC/DH;
signatures are RSA/ElGamal/Schnorr/ECDSA. The existing crypto functions implement
these choices. AES keys are 128/192/256 bits, DES 64 stored bits, and 3DES
128/192 stored bits. AES blocks are always 16 bytes; DES/3DES blocks are 8 bytes.

Schnorr, ElGamal and DH use the fixed public 2048-bit prime from
[RFC 7919](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1), with fresh
private keys. Keep `group_bits=2048`; other public group sizes are unsupported.
No public group-prime generation or cache is needed.

Edit `prepare_record()` and the matching checks in `accept_record()` when the
question changes the record fields or asks for a separate signature over its
hash. This is a readable starting point to adapt to the paper.

## Files and reruns

The program reuses saved keys and records in the same `DATA_DIR`. Each run starts
with collection open. Only the **Close collection** menu action closes it,
after pending reports have been verified. There is no collection timer.
Time is used only for report timestamps and timestamp searches.
Private keys are in `private/`, public keys in
`public.json`, and packages/results/index/totals in `records.json`.
The server key file never holds the numeric private key in threshold mode.

Changing crypto algorithms, the release mode or voting choices requires
compatible fresh files. Labels can be edited without replacing keys. Configure
registered IDs before setup; new accounts need their own signing keys.
Initial threshold Paillier setup still generates secret safe primes and can
take time; later runs reuse saved keys. Its secret primes are separate from the
fixed public group prime.

## Lab limits

The HMAC index supports keyed equality search; it reveals equality/access
patterns. ECC/DH wrapping uses key agreement plus HKDF and AES-GCM. Raw RSA
arithmetic is separate from RSA-OAEP session-key wrapping. Keep integer
sums/products below the arithmetic modulus to avoid modular wraparound.

The [DJN threshold construction](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf)
uses real trustee partial decryptions, not approval counters. This lab version
assumes honest trustees and omits proofs of correct partial decryption. Client
validation does not prove to the server that encrypted amounts or votes are in
range; that would require additional proofs.


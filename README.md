# PAF Credentials Checker

PCC's aim is to provide a high performing offline tool to easily assess which users are vulnerable to Password Reuse Attacks (a.k.a. *Password Stuffing*). The output of this tool is usually used to communicate with the vulnerable users to force them to change their password to one that has not leaked online.

## Features Highlights

- Only checks the password of internal users matching the IDs in external lists
- Highly parallel checking of credentials (defaults to 30 goroutines)
- Supports mixed internal hashing functions, useful if you have multiple hashing schemes
- Easy to extend and add your own internal hashing schemes

## Getting Started

If you have a working Go environment, building the tool after cloning this repository should be as easy as running:
```
go build
```

The tool can be then launched using this command:
```
./paf-credentials-checker -creds credentials.txt -outfile cracked.txt leak1.txt [leak2.txt [leakN.txt ...]]
```
You can find some test cases in the `test_files` directory.

The different files on the command line are:
- `credentials.txt` contains your internal credentials, with one record per line following this syntax
  - `internalID0:InternalID1:mappingID:hashtype:hash:[salt[:salt[:...]]` 
    - `internalID0` and `internalID1` are internal identifiers that will be written to the output file.
    - `mappingID` is an ID that will be used to map the internal user to the external passwords lists
    - `hashtype` is the *short* hash type that corresponds to the hashing function that should be used to parse the hash and salts and to check the credentials
    - `hash` and `salts`, in the format required by the checking and extracting functions
- `cracked.txt` is a csv file in which each *password reuse match* will appear as a row containing the `internalID0,internalID1` of the matched user. This file is being written *live*, so **it will contain duplicates if your *leak* files contain duplicates**.
- `leak.txt` is a file in the usual *combo list* format:
  - `mappingID:password`

**Note:** Usually the `mappingID` in the combo lists are usernames, emails or others fields containings PIIs. To avoid processing and storing  those extremely sensitive information, a script is available in the `importer` directory to recreate combo lists files and change the `mappingID` with a heavily truncated md5 sum (by default first 6 characters of the hex output). Applying the same function to your internal `mappingID` will allow the matching logic to continue working. Please note that using a truncated hash that short **will likely** create some false positives (e.g. an internal user being matched to an external one that is not the same), but:
- this is expected, we **want** collisions to happen to limit the sensitivity of the information
- if there is a full false positive (e.g. an internal user matched to another external one that somehow had the same password), then the internal user probably used an extremely common password. Therefore it's not a bad idea to also ask him to change his password...

## Supported hashing functions
In this initial release, only two functions are implemented to showcase the different functionalities.

| Short ID | Verbose ID | Function |
|---|---|---|
| `MD5` | `MD5RAW` | `md5(password)` |
| `MD5spSHA1sp` | `MD5SaltPreSHA1SaltPre` | `md5(salt1.UPPER(HEX(sha1(salt2.password))))`|

## Adding a new hashing function
Here is a todo list to add a new hashing function:
- [ ] Decide on a *Short ID*, used in your internal credentials file, and a *Verbose ID*, only used **within** the tool.
- [ ] Add the *Verbose ID* to the const list line 14 in `credentialChecker.go`
- [ ] Add a case in the `detectHash` function in `extractHash.go` to map the *Short ID* to the *Verbose ID*
- [ ] Create your *extraction* function in `extractHash.go`. The purpose of the extraction function is to parse the line from the internal credentials file from the hashtype field until the end and to create a new `Hash` object containing the proper *hashtype* (*Verbose ID*), *hash* and *salts* values.
- [ ] Add a case `extractTokens` function to map your *Verbose ID* with your new extraction function.
- [ ] Create your *checking* function in `checkHash.go`. The purpose of this function is to check a clear text password against the `Hash` object that was extracted in the previous step.
- [ ] Add a case with the *Verbose ID* in the function `crackHash` function in `credentialChecker.go` to map it to your new checking function
- [ ] Add new unit tests to verify that your extraction and checking functions are working accordingly

## Motivation

While comparing users's passwords against known weak passwords is a best practice, using a massive list containing all the leaked passwords is both impractical if you have a lot of users and a strong hashing function, and also really bad from a user experience point of view as they will struggle to find a password that didn't appear in any breaches.

However, relying on a more realistic blacklist of around 10.000 passwords will protect the users against attacker *spraying* bad passwords at scale but it will not help them in case they are reusing their password on another website that has suffered a breach. In this scenario, an attacker would just need to get those credentials from this third party website leak and test them on your website. If the user used the same password on both services, even if it was a strong password, his account would be at immediate risk of compromise. This attack scenario, called *Password Stuffing* or *Password Reuse Attack* has been trendy for several years as more and more massive data leaks are happening.

This tool's aim is to fill this gap by allowing you to:
- Flag accounts that have been reusing the same set of credentials internally and on leaked websites
- Easily extend the tool to implement your own internal hashing function

This tool maps IDs from the internal list with IDs in the external lists to only check credentials belonging to internal users for password reuse to avoid the pitfalls mentioned above. It is also highly parallel thanks to Go's goroutines (by default it creates 30 computing threads, tunable in the code).

## License

This project is licensed under the The 3-Clause BSD License - see the [LICENSE.md](LICENSE.md) file for details

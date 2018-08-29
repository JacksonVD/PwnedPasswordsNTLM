# PwnedPasswordsNTLM
Basic binary search on a sorted file containing NTLM hashes from Pwned Passwords or any set of NTLM hashes.
Iterates line by line over an input file, conducts a binary search over the dataset to search for the hash in the current line. Outputs to file a list of users with breached passwords.

Note: requires that the input file be in Hashcat format (Username:Hash).

For more details on how to extract the hashes, and further background, please see my post here - http://jacksonvd.com/pwned-passwords-and-ntlm-hashes

# Usage
PwnedPasswordsNTLM \<Path to Dataset> \<Input File Path> \<Output File Path>

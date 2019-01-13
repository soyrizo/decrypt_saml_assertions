SAML Decryption Tool
====================

Will need to provide private key location in `main.go`.

Generates a decrypted assertion file with a Unix timestamp.   
*e.g. 1536887938_decrypted_assertion.xml*


Usage
-----
`./go_binary encrypted_assertion.xml`  


Compile
-------
go build main.go

To Do
-----
- Option to pass in private key location instead of hard coding it.

License
-------
SAML descryption tool is released under the [MIT License](https://choosealicense.com/licenses/mit/).

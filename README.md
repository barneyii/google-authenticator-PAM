Google Authenticator PAM
========================

This is a fork of https://code.google.com/p/google-authenticator that adds a security enhancement so that it can be used to secure applications for already logged in users. Using a similar approach to the unix_chkpwd utility of unix_pam, it adds an option to use a setuid helper utility for validating codes. This allows the secret files(s) to be made unreadable by anyone except the owner of the helper utility. Without this feature, the secrets are exposed to any logged in user and so the PAM cannot be used to secure anything against users that have already logged in.
One possible use-case that is enabled by this enhancement is to secure sudo with Google Authenticator so that users can log in with normal privileges using a standard username and password or private key, but only elevate their privileges to root using an additional one-time password provided by Google Authenticator.

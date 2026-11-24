# Connect to eduroam

Open a terminal and run `connect-eduroam` or
`~/auto-eduroam/connect-eduroam.sh`. The helper uses NetworkManager to find
eduroam and verify the school's authentication server. Enter the CA
certificate and server domain your school provides. If your school
specifies system certificates, enter `/etc/ssl/cert.pem` at the certificate
prompt. Enter your school password when NetworkManager prompts for it.

The separate `connect-eduroam-upstream` command runs the original
two-prompt setup. It replaces an existing profile named `eduroam`, skips
authentication server verification, and saves the password in NetworkManager.

The two-prompt script ships byte for byte from the pinned
[auto-eduroam revision](https://github.com/frankischilling/auto-eduroam/tree/23e25f0cdb1d87e0e3857fcc095fcc2826d9b2fe).

# Connect to eduroam

Open a terminal and run `connect-eduroam` or
`~/auto-eduroam/connect-eduroam.sh`. The pinned upstream script uses
NetworkManager to find eduroam and prompts for your school username and
password. It creates a PEAP/MSCHAPv2 profile, replacing any existing
profile named `eduroam`.

The upstream script skips authentication server verification and saves the
password in NetworkManager. Use your school's official setup profile or
`connect-eduroam-verified` for certificate and server-name checks. If your
school specifies system certificates, enter `/etc/ssl/cert.pem` at the
verified helper's certificate prompt and use the domain your school lists.

The two-prompt script ships byte for byte from the pinned
[auto-eduroam revision](https://github.com/frankischilling/auto-eduroam/tree/23e25f0cdb1d87e0e3857fcc095fcc2826d9b2fe).

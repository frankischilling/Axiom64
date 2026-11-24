# Connect to eduroam

Get the CA certificate and authentication server domain from your school.
Open a terminal and run `~/auto-eduroam/connect-eduroam.sh`. The helper
uses NetworkManager to scan for eduroam and create a PEAP/MSCHAPv2 profile
for your account. Enter your password when NetworkManager prompts for it.

Wi-Fi and NetworkManager must be running. Reconnect from Plasma or run
`nmcli --ask connection up "Axiom64 eduroam"` after creating the profile.

This helper is adapted from [auto-eduroam](https://github.com/frankischilling/auto-eduroam).

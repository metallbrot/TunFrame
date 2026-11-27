# DNSExfiltrator client

Client of the DNSExfiltrator version used by TunFrame. Protocol, options, how TunFrame runs it and known limitations: [documentation/dnsexfiltrator.md](../../documentation/dnsexfiltrator.md).

`data/` is mounted into the container at `/data`: put the files to exfiltrate there (they are not versioned). TunFrame writes `data/domains.txt` and `data/logs/client.log`.

Based on [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) by Arno0x, as modified by Kristijan Žiža. If you use this tool for research, please cite:

> Žiža, K., Tadić, P. & Vuletić, P. *DNS exfiltration detection in the presence of adversarial attacks and modified exfiltrator behaviour.* Int. J. Inf. Secur. (2023). <https://doi.org/10.1007/s10207-023-00723-w>

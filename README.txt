Objective and Sample Output
The objective of this project is to implement a DNS resolver that will look up IPv4 (A
records) or IPv6 addresses (AAAA records) along with their digital signatures.
The resolver program should read a mandatory domain name as input from the command
line followed by an optional RRTYPE code (A or AAAA). An example would be
myresolver www.nlnetlabs.nl AAAA
The resolver then issues a series or iterative queries to obtain the IPv6 addresses (AAAA
records) or IPv4 addresses (A records) along with any DNSSEC signatures (RRSIG
records) for this hostname. Note: not all domain names have DNSSEC. Executing the
command illustrated above for resolving www.nlnetlabs.nlshould result in output
similar to the output of ANSWER section of a DIG command:
www.nlnetlabs.nl. 10151 IN AAAA 2a04:b900::1:0:0:10
www.nlnetlabs.nl. 10151 IN RRSIG AAAA 8 3 10200
20141112005013 20141015005013 42393 nlnetlabs.nl.
mFhiqFsSAD+DID7wTKfDCP5/cvR/dlzLGPc8dvRsaRcSrLNsH8gFTF7m
HvFHHPuTAT9235c14f3FT+qc+RB7dwjr/94WzOcLimZBACbif+gXILiV
7dtGiLQmO90MleG/MaiYm7HX5o+/aGoH973lda9zyofqcid08HEfPRTt
uDo=
Note that since this is live data, the number of addresses and their values may change.
As another example, running either of the commands
myresolver www.cnn.com A
or
myresolver www.cnn.com 
should produce output similar to the following. (Note, no RRSIG records were
available):
www.cnn.com. 600 IN CNAME www.cnn.com.vgtf.net.
www.cnn.com.vgtf.net. 30 IN CNAME cnn-
56m.gslb.vgtf.net.
cnn-56m.gslb.vgtf.net. 30 IN A 157.166.249.11
cnn-56m.gslb.vgtf.net. 30 IN A 157.166.248.10
cnn-56m.gslb.vgtf.net. 30 IN A 157.166.248.11
cnn-56m.gslb.vgtf.net. 30 IN A 157.166.249.10
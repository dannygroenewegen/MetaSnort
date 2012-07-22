MetaSnort
=========

Beating Metasploit with Snort

Earlier research has shown that the effectiveness of Snort against the Metasploit Framework is very low. We made an attempt to improve the detection rate by automatically converting modules of the Metasploit Framework to Snort rules. Based on our analysis of the Metasploit modules we automated the process of generating Snort rules to detect payloads. Our tests have shown that the detection rates increased compared to the numbers based on earlier research. The results look promising, but need some further analysis. Especially encoders are still an unresolved issue.
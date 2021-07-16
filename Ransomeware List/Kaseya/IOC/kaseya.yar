/* Source: https://github.com/Neo23x0/signature-base/blob/e360605894c12859de36f28fda95140aa330694b/yara/crime_ransom_revil.yar
*/


rule MAL_RANSOM_REvil_Oct20_1 {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-10-13"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      hash4 = "fc26288df74aa8046b4761f8478c52819e0fca478c1ab674da7e1d24e1cfa501"
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b }
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff }
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 }
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff }
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      2 of them or 4 of them
}

/* Source: https://github.com/bartblaze/Yara-rules/blob/master/rules/ransomware/REvil_Cert.yar
*/

import "pe"
rule REvil_Cert
{
meta:
	description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
	tlp = "White"
	
condition:
	uint16(0) == 0x5a4d and
		for any i in (0 .. pe.number_of_signatures) : (
		pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0"
	)
}


/* Source: https://github.com/bartblaze/Yara-rules/blob/master/rules/ransomware/REvil_Dropper.yar
*/

rule REvil_Dropper
{
meta:
	description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
	author = "@bartblaze"
	date = "2021-07"
	hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"
  	reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
	tlp = "White"
	
strings:
  $ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
  d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
  87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
  43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
  5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
  00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
  38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
  56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
  50 ff 15 28 d0 40 00 }
	
condition:
	all of them
}



/* Source: https://github.com/Neo23x0/signature-base/blob/master/yara/crime_revil_general.yar
*/

rule APT_MAL_REvil_Kaseya_Jul21_2 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
      hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
      hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }

      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and ( 2 of ($opa*) or 3 of them )
}

/* Source: https://github.com/Neo23x0/signature-base/blob/master/yara/crime_revil_general.yar
*/

import "pe"

rule APT_MAL_REvil_Kaseya_Jul21_1 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
      hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
      hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
      hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
   strings:
      $s1 = "Mpsvc.dll" wide fullword
      $s2 = ":0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:H<L<P<\\<`<" ascii fullword

      $op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
      $op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
      $op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
      $op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
      $op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      (
         pe.imphash() == "c36dcd2277c4a707a1a645d0f727542a" or
         2 of them
      )
}

rule APT_MAL_REvil_Kaseya_Jul21_2 {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
      hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
      hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }

      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and ( 2 of ($opa*) or 3 of them )
}
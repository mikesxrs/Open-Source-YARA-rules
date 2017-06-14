rule Wanna_Cry_Ransomware_Generic {
       meta:
              description = "Detects WannaCry Ransomware on Disk and in Virtual Page"
              author = "US-CERT Code Analysis Team"
              reference = "not set"
              date = "2017/05/12"
       hash0 = "4DA1F312A214C07143ABEEAFB695D904"
       strings:
              $s0 = {410044004D0049004E0024}
              $s1 = "WannaDecryptor"
              $s2 = "WANNACRY"
              $s3 = "Microsoft Enhanced RSA and AES Cryptographic"
              $s4 = "PKS"
              $s5 = "StartTask"
              $s6 = "wcry@123"
              $s7 = {2F6600002F72}
              $s8 = "unzip 0.15 Copyrigh"
              $s9 = "Global\\WINDOWS_TASKOSHT_MUTEX"
              $s10 = "Global\\WINDOWS_TASKCST_MUTEX"
             $s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
             $s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
             $s13 = "WNcry@2ol7"
             $s14 = "wcry@123"
             $s15 = "Global\\MsWinZonesCacheCounterMutexA"
       condition:
              $s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}
/*The following Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/
rule MS17_010_WanaCry_worm {
       meta:
              description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
              author = "Felipe Molina (@felmoltor)"
              reference = "https://www.exploit-db.com/exploits/41987/"
              date = "2017/05/12"
       strings:
              $ms17010_str1="PC NETWORK PROGRAM 1.0"
              $ms17010_str2="LANMAN1.0"
              $ms17010_str3="Windows for Workgroups 3.1a"
              $ms17010_str4="__TREEID__PLACEHOLDER__"
              $ms17010_str5="__USERID__PLACEHOLDER__"
              $wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
              $wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
              $wannacry_payload_substr3 = "tpGFEoLOU6+5I78Toh/nHs/RAP"
       condition:
              all of them
}

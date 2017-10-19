rule MPAMedia9002_dll
{
    meta:
        decription = "9002 trojan family, MPAMedia.dll"
        author = "HPSR"
        reference = "E48A4CB7325ADCB38127A95AD47CD24D"
        reference2 = "https://community.saas.hpe.com/t5/Security-Research/9002-RAT-a-second-building-on-the-left/ba-p/228686#.WaBdzB9ifW8"
        date = "11/8/2016"
    strings:
        $opCode010 = {8D 45 ?? C7 45 ?? 56 69 72 74 33 DB C7 45 ?? 75 61 6C 50 50}
        $opCode060 = {C7 45 ?? 72 6F 74 65 66 C7 45 ?? 63 74 88 5D ?? C7 45 ?? 6B 65 72 6E}
        $opCode100 = {C7 45 ?? 65 6C 33 32 88 5D ?? C7 45 ?? 47 65 74 53 C7 45 ?? 79 73 74 65}
        $opCode140 = {c7 45 ?? 6D 54 69 6D 66 C7 ?? EC 65 00}
    condition:
        all of them
}

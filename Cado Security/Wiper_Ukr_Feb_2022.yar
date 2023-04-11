rule Wiper_Ukr_Feb_2022 {
    meta:
      description = "Detects Wiper seen in Ukraine 23rd Feb 2022"
      author = "cadosecurity.com"
      date = "2022-02-23"
      license = "Apache License 2.0"
      hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      ref1 = "https://twitter.com/threatintel/status/1496578746014437376"
      ref2 = "https://twitter.com/ESETresearch/status/1496581903205511181"
      report = "https://github.com/cado-security/wiper_feb_2022"
    strings:
        $ = "Hermetica Digital Ltd" wide ascii
        $ = "DRV_XP_X64" wide ascii
        $ = "Windows\\System32\\winevt\\Logs" wide ascii
        $ = "EPMNTDRV\\%u" wide ascii
    condition:
      uint16(0) == 0x5A4D and all of them
}
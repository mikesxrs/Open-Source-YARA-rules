rule malware_red_leaves_generic {
  meta:
    author = "David Cannings/nccgroup"
    description = "Red Leaves malware, related to APT10"
    reference = "https://github.com/nccgroup/Cyber-Defence/tree/master/Signatures/yara"

    // This hash from VT retrohunt, original sample was a memory dump
    sha256 = "2e1f902de32b999642bb09e995082c37a024f320c683848edadaf2db8e322c3c"

  strings:
    // MiniLZO release date
    $ = "Feb 04 2015"
    $ = "I can not start %s"
    $ = "dwConnectPort" fullword
    $ = "dwRemoteLanPort" fullword
    $ = "strRemoteLanAddress" fullword
    $ = "strLocalConnectIp" fullword
    $ = "\\\\.\\pipe\\NamePipe_MoreWindows" wide
    $ = "RedLeavesCMDSimulatorMutex" wide
    $ = "(NT %d.%d Build %d)" wide
    $ = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0;
      SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C;
      .NET4.0E)" wide
    $ = "red_autumnal_leaves_dllmain.dll" wide ascii
    $ = "__data" wide
    $ = "__serial" wide
    $ = "__upt" wide
    $ = "__msgid" wide

  condition:
    7 of them
}

rule malware_red_leaves_memory {
  meta:
    author = "David Cannings/nccgroup"
    description = "Red Leaves C&C left in memory, use with Volatility / Rekall"
    reference = "https://github.com/nccgroup/Cyber-Defence/tree/master/Signatures/yara"

  strings:
    $ = "__msgid=" wide ascii
    $ = "__serial=" wide ascii
    $ = "OnlineTime=" wide

    // Indicates a file transfer
    $ = "clientpath=" wide ascii
    $ = "serverpath=" wide ascii

  condition:
    3 of them
}

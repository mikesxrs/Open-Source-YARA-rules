rule AutoIt_Script {
    meta:
    description = "AutoIt Script - used by attackers"
   
    strings:    
        $keyword1 = "#include <FTPEX.au3>"
        $keyword2 = "#include <updateftp.au3>"
        $keyword3 = "#include <WinAPI.au3>"
        $keyword4 = "Global $FTPServer" fullword
        $keyword5 = "Global $FTPUser" fullword
        $keyword6 = "= _FTP_Connect"
       
    condition:
    1 of ($keyword*)
}
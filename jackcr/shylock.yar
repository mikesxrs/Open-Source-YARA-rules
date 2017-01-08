rule memory_shylock

{

   strings:
      $a = /pipe\\[A-F0-9]{32}/     //Named pipe created by the malware
      $b = /id=[A-F0-9]{32}/     //Portion or the uri beacon
      $c = /MASTER_[A-F0-9]{32}/     //Mutex created by the malware
      $d = "***Load injects by PIPE (%s)" //String found in binary
      $e = "***Load injects url=%s (%s)" //String found in binary
      $f = "*********************** Ping Ok ************************" //String found in binary
      $g = "*** LOG INJECTS *** %s"     //String found in binary

   condition: 
      any of them

}

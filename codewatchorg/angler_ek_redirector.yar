rule AnglerEKredirector
{
   meta:
      description = "Angler Exploit Kit Redirector"
      ref = "http://blog.xanda.org/2015/08/28/yara-rule-for-angler-ek-redirector-js/"
      author = "adnan.shukor@gmail.com"
      date = "08-July-2015"
      impact = "5"
      version = "1"
   strings:
      $ekr1 = "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" fullword
      $ekr2 = "document.cookie=\"PHP_SESSION_PHP="
      $ekr3 = "path=/; expires=\"+date.toUTCString();</script>" fullword
      $ekr4 = "<iframe src=" fullword
      $ekr5 = "</iframe></div>" fullword
   condition:
      all of them
}
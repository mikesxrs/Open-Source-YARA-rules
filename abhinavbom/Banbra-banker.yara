rule banbra : banker
{
meta: 
    author = "@abhinavbom"
    maltype = "NA"
    version = "0.1"
    date = "8/06/2015"
strings: 
    $a = "senha" fullword nocase
    $b = "cartao" fullword nocase
    $c = "caixa" 
    $d = "login" fullword nocase
    $e = ".com.br"

condition:
    #a > 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3              
}
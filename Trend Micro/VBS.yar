rule layer1_vbs
{
meta:
	author = "Trendmicro"
	reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/from-cybercrime-to-cyberpropaganda/"
strings:
	$vbs = /[a-z]+ = [a-z]+ & ChrW\(AscW\(Mid\([a-z]+, [a-z]+, 1\)\) - [a-z]+ \* [a-z]+\)/ wide
condition:
$vbs
}

rule layer0_vbs
{
meta:
	author = "Trendmicro"
	reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/from-cybercrime-to-cyberpropaganda/"
strings:
	$code = /Dim \w+\s+\r\n\s+For Each \w+ In split\(\w+,".+"\)\r\n\s+\w+ = \w+ & ChrW\(\w+ - "\d+"\)/
condition:
$code
}


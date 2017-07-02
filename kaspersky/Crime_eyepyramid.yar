rule crime_ZZ_EyePyramid {
meta:
copyright = " Kaspersky Lab"
author = " Kaspersky Lab" 
maltype = "crimeware"
filetype = "Win32 EXE"
date = "2016­01­11" version = "1.0"
strings:
$a0="eyepyramid.com" ascii wide nocase fullword
$a1="hostpenta.com" ascii wide nocase fullword
$a2="ayexisfitness.com" ascii wide nocase fullword
$a3="enasrl.com" ascii wide nocase fullword
$a4="eurecoove.com" ascii wide nocase fullword
$a5="marashen.com" ascii wide nocase fullword
$a6="millertaylor.com" ascii wide nocase fullword
$a7="occhionero.com" ascii wide nocase fullword
$a8="occhionero.info" ascii wide nocase fullword
$a9="wallserv.com" ascii wide nocase fullword
$a10="westlands.com" ascii wide nocase fullword
$a11="217.115.113.181" ascii wide nocase fullword
$a12="216.176.180.188" ascii wide nocase fullword
$a13="65.98.88.29" ascii wide nocase fullword
$a14="199.15.251.75" ascii wide nocase fullword
$a15="216.176.180.181" ascii wide nocase fullword
$a16="MN600­849590C695DFD9BF69481597241E­668C" ascii wide nocase fullword
$a17="MN600­841597241E8D9BF6949590C695DF­774D" ascii wide nocase fullword
$a18="MN600­3E3A3C593AD5BAF50F55A4ED60F0­385D" ascii wide nocase fullword
$a19="MN600­AD58AF50F55A60E043E3A3C593ED­874A" ascii wide nocase fullword
$a20="gpool@hostpenta.com" ascii wide nocase fullword
$a21="hanger@hostpenta.com" ascii wide nocase fullword
$a22="hostpenta@hostpenta.com" ascii wide nocase fullword
$a23="ulpi715@gmx.com" ascii wide nocase fullword
$b0="purge626@gmail.com" ascii wide fullword
$b1="tip848@gmail.com" ascii wide fullword
$b2="dude626@gmail.com" ascii wide fullword
$b3="octo424@gmail.com" ascii wide fullword
$b4="antoniaf@poste.it" ascii wide fullword
$b5="mmarcucci@virgilio.it" ascii wide fullword
$b6="i.julia@blu.it" ascii wide fullword
$b7="g.simeoni@inwind.it" ascii wide fullword
$b8="g.latagliata@live.com" ascii wide fullword
$b9="rita.p@blu.it" ascii wide fullword
$b10="b.gaetani@live.com" ascii wide fullword
$b11="gpierpaolo@tin.it" ascii wide fullword
$b12="e.barbara@poste.it" ascii wide fullword
$b13="stoccod@libero.it" ascii wide fullword
$b14="g.capezzone@virgilio.it" ascii wide fullword
$b15="baldarim@blu.it" ascii wide fullword
$b16="elsajuliette@blu.it" ascii wide fullword
$b17="dipriamoj@alice.it" ascii wide fullword
$b18="izabelle.d@blu.it" ascii wide fullword
$b19="lu_1974@hotmail.com" ascii wide fullword
$b20="tim11235@gmail.com" ascii wide fullword
$b21="plars575@gmail.com" ascii wide fullword
$b22="guess515@fastmail.fm" ascii wide fullword
condition:
((uint16(0) == 0x5A4D)) and (filesize < 10MB) and ((any of ($a*)) or (any of ($b*)) )
}

rule phoenix_html2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "2fd263f5d988a92715f4146a0006cb31"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Pec.lilsD)E)i-gonP(mgge.eOmn"
	$string1 = "(trt;oo"
	$string2 = "aceeC:0h"
	$string3 = "Vubb.oec.n)a."
	$string4 = "t;o{(bspd}ci:0OO[g(cfjdh}1sN}ntnrlt;0pwf{-"
	$string5 = "seierb)gMle(}ev;is{(b;ga"
	$string6 = "e)}ift"
	$string7 = "Dud{rt"
	$string8 = "blecroeely}diuFI-"
	$string9 = "ttec]tr"
	$string10 = "fSgcso"
	$string11 = "eig.t)eR{t}aeesbdtbl{1sr)m"
	$string12 = ").}n,Raa.s"
	$string13 = "sLtfcb.nrf{Wiantscncad1ac)scb0eo]}Diuu(nar"
	$string14 = "dxc.,:tfr(ucxRn"
	$string15 = "eDnnforbyri(tbmns).[i.ee;dl(aNimp(l(h[u[ti;u)"
	$string16 = "}tn)i{ebr,_.ns(Nes,,gm(ar.t"
	$string17 = "l]it}N(pe3,iaaLds.)lqea:Ps00Hc;[{Euihlc)LiLI"
condition:
	17 of them
}

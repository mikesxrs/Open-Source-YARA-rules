rule ALFA_TEaM_Shell_V1
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for ALFA TEaM Shell"
        Reference = "https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html"
        Date = "2017-10-28"
		
  strings:
		$STR1 = "#Iranian Hackers"
		$STR2 = "#Persian Gulf For Ever"
		$STR3 = "#Special Thanks To MadLeets"
		$STR4 = "function alfa("
		$STR5 = "=alfa("
		$STR6 = "#Author Sole Sad & Invisible"
		$STR7 = "#solevisible@gmail.com"
		$STR8 = "#CopyRight 2014"
		
	condition:
		5 of them
}

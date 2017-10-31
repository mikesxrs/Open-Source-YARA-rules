rule IRONGATE_SCADA
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for ALFA TEaM Shell"
        Reference = "https://www.fireeye.com/blog/threat-research/2016/06/irongate_ics_malware.html"
        Date = "2017-10-28"
		
  strings:
		$STR1 = "PackingModule.exe"
		$STR2 = "DllProxyInstaller"
		$STR3 = "FindFile"
		$STR4 = "FindFileInDrive"
		$STR5 = "InstallProxy"
		$STR6 = "dllFilename"
		$STR7 = "newDllFilename"
		$STR8 = "PackingModule.Step7ProSim.dll"
		$STR9 = "ccc64bc5-ef95-4217-adc4-5bf0d448c272"
		$STR10 = "c:\\Users\\Main\\Desktop\\PackagingModule\\PackagingModule\\obj\\Release\\PackagingModule.pdb"
		$STR11 = "Step7ProSim.dll"
		$STR12 = "IStep7ProSim"
		$STR13 = "Step7ProSim.Interfaces"
		$STR14 = "waitBeforeRecordingTimeInMilliSeconds"
		$STR15 = "waitBeforePlayingRecordsTimeInMilliSeconds"
		$STR16 = "payloadExecutionTimeInMilliSeconds"
		$STR17 = "waitBeforePlayingRecordsTimer"
		$STR18 = "waitBeforeExecutionTimer"
		$STR19 = "waitBeforeRecordingTimer"
		$STR20 = "payloadExecutionTimer"
		$STR21 = "Step7ProSimProxy"
		$STR22 = "$863d8af0-cee6-4676-96ad-13e8540f4d47"
		$STR23 = "c:\\Users\\Main\\Desktop\\Step7ProSimProxy\\obj\\Release\\Step7ProSim.pdb"
	condition:
		11 of them
}

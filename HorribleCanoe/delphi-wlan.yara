rule delphi_wlan {
	strings:
		$dll = "wlanapi.dll"

		$api2 = "WlanOpenHandle"
		$api3 = "WlanCloseHandle"
		$api4 = "WlanEnumInterfaces"
		$api5 = "WlanQueryInterface"
		$api6 = "WlanGetAvailableNetworkList"

		$options1 = "80211_OPEN"
		$options2 = "80211_SHARED_KEY"
		$options3 = "WPA_PSK"
		$options4 = "WPA_NONE"
		$options5 = "RSNA"
		$options6 = "RSNA_PSK"
		$options7 = "IHV_START"
		$options8 = "IHV_END"
		$options9 = "WEP104"
		$options10 = "WPA_USE_GROUP OR RSN_USE_GROUP"
		$options11 = "IHV_START"
		$options12 = "IHV_END"
		$options13 = "WEP40"

	condition:
		$dll and 3 of ($api*) and 6 of ($options*)
}
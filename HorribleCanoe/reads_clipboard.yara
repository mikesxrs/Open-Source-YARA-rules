rule reads_clipboard {
	strings:
		$clipboard1 = "CloseClipboard"
		$clipboard2 = "EmptyClipboard"
		$clipboard3 = "EnumClipboardFormats"
		$clipboard4 = "GetClipboardData"
		$clipboard5 = "IsClipboardFormatAvailable"
		$clipboard6 = "OpenClipboard"
		$clipboard7 = "RefreshClipboard"
		$clipboard8 = "RegisterClipboardFormat"
		$clipboard9 = "SendYourClipboard"
		$clipboard10 = "SetClipboardData"

	condition:
		5 of them
}

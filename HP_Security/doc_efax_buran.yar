rule doc_efax_buran {
	meta:
		author = "Alex Holland (@cryptogramfan)"
        reference = "https://threatresearch.ext.hp.com/buran-ransomware-targets-german-organisations-through-malicious-spam-campaign/"
		date = "2019-10-10"
		sample_1 = "7DD46D28AAEC9F5B6C5F7C907BA73EA012CDE5B5DC2A45CDA80F28F7D630F1B0"
		sample_2 = "856D0C14850BE7D45FA6EE58425881E5F7702FBFBAD987122BB4FF59C72507E2"
		sample_3 = "33C8E805D8D8A37A93D681268ACCA252314FF02CF9488B6B2F7A27DD07A1E33A"
		
	strings:
		$vba = "vbaProject.bin" ascii nocase
		$image = "image1.jpeg" ascii nocase
		$padding_xml = /[a-zA-Z0-9]{5,40}\d{10}\.xml/ ascii
		
	condition:
		all of them and filesize < 800KB
}

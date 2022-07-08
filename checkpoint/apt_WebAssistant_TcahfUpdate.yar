rule apt_WebAssistant_TcahfUpdate {
meta:
    description = "Rule for detecting the fake WebAssistant and TcahfUpdate applications used to target the Uyghur minority"
    reference = "https://research.checkpoint.com/2021/uyghurs-a-turkic-ethnic-minority-in-china-targeted-via-fake-foundations/"
    version = "1.0"
    last_modified = "2021-05-06"
    hash = "2f7492423586a3061e5641b5b271ca54"
    hash = "1b5dbd351bb7159eb08868c46a3fe3a6"
    hash = "90fcbd5c904326466c3b6af1ca34aae1"
strings:
    $url = {2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 2f [0-50] 2e 00 70 00 79 00 3f 00}
    $lib = "Newtonsoft.Json"
    $mac = "MACAddress Is Not NULL" wide
condition:
    uint16(0)==0x5A4D and $url and $lib  and $mac
    and filesize < 1MB
}

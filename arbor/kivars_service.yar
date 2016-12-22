rule kivars_service	
{
  meta:
    description	=	"Detects instances of	Kivars malware when	installed as a service"
    author = "cwilson@arbor.net"
    SHA-256	=	"443d24d719dec79a2e1be682943795b617064d86f2ebaec7975978f0b1f6950d"
    SHA-256	=	"44439e2ae675c548ad193aa67baa8e6abff5cc60c8a4c843a5c9f0c13ffec2d8"
    SHA-256	=	"74ed059519573a393aa7562e2a2afaf046cf872ea51f708a22b58b85c98718a8"
    SHA-256	=	"80748362762996d4b23f8d4e55d2ef8ca2689b84cc0b5984f420afbb73acad1f"
    SHA-256	=	"9ba14273bfdd4a4b192c625d900b29e1fc3c8673154d3b4c4c3202109e918c8d"
    SHA-256	=	"fba3cd920165b47cb39f3c970b8157b4e776cc062c74579a252d8dd2874b2e6b"
    reference = "https://www.arbornetworks.com/blog/asert/wp-content/uploads/2016/04/ASERT-Threat-Intelligence-Report-2016-03-The-Four-Element-Sword-Engagement.pdf"
  strings:
    $s1	=	"\\Projects\\Br2012\\Release\\svc.pdb"
    $s2	=	"This	is a flag"
    $s3	=	"svc.dll"
    $s4	=	"ServiceMain"
    $s5	=	"winsta0"
  condition:
    uint16(0) == 0x5A4D and filesize	<	1000000 and	(all of	($s*))
}

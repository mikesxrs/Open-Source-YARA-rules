import "pe"

rule UPX_Packed
{
	condition:
		pe.sections[0].name contains "UPX0" and
		pe.sections[1].name contains "UPX1"
}
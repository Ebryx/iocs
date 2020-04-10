import "hash"
import "pe"

rule sidewinder_stage1_dropper : APT_SideWinder {
	
	meta:
		version = "1.0"
		author = "Ebryx (Pvt.) Ltd."
		copyright = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects dropped HTA file"
		hash1 = "34ab2e72624e808efa66cccb9ea2ec086b02927165dfc00d477cf573ffff2761"
		hash2 = "eafcf556108c01ca395baecb1f016e1ead9f7bc5dc7e176326cf4f89b7400441"
		tlp = "White"

	strings:
		$cnc1 = "o.pink" fullword
		$cnc2 = "o.Work" fullword

		$enum3 = "finally{window.close()" fullword
		$enum4 = "fileEnum" fullword
		$enum5 = "fileEnum.moveFirst()" fullword
		$enum6 = "GetFolder"
		$enum7 = "GetSpecialFolder"

		$com1 = "<script" 
		$com2 = "javascript"
		$com3 = "</script>"


	condition:
		filesize >= 300KB and (1 of ($cnc*) and 2 of ($com*) and 3 of ($enum*))
}

rule sidewinder_linkzip_dll : APT_SideWinder {
	
	meta:
		version = "1.0"
		author = "Ebryx (Pvt.) Ltd."
		copyright = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects of SideWinder's LinkZip DLL"
		hash = "08588edcd50c3d5a81531e0ecfe8b01a105d4ce93a3084f268ddf23cddbf44c9"
		tlp = "White"

	strings:
		$str1 = "James Forshaw 2017" fullword ascii
		$str2 = "LegalCopyrightCopyright"
		$str3 = "OriginalFilenameLinkZip.dll@"
		$str4 = "/_CorDllMainmscoree.dll"
		$str5 = "WinHttp.WinHttpRequest"
		$str6 = "$Example Assembly for DotNetToJScript"
		$str7 = "$56598f1c-6d88-4994-a392-af337abe5777" fullword ascii
		$str8 = "'System.Reflection.Assembly Load(Byte[])" fullword ascii
		$str9 = "mshta.exe"

	condition:
		filesize < 4KB and (7 of ($str*)) and uint16be(0) == 0x4D5A
}

rule sidewinder_duser_dll : APT_SideWinder {
	
	meta:
		version = "1.0"
		author = "Ebryx (Pvt.) Ltd."
		copyright = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects of SideWinder's DUser DLL"
		hash = "c69456894fb70e6dfb4ef38bc926f8fc90a82a7b9427f429581a7cee22e09411"
		tlp = "White"

	strings:
		$ep = { FF 25 00 20 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

		$str1 = "$92d2f2dd-43d1-49a9-9ab5-b56ad3eb4af9"
		$str2 = "_CorDllMain"
		$str3 = "\\DUSER.dll"
		$str4 = "mscoree.dll"
		$str5 = "copytight @"
		$str6 = "System.Diagnostics" fullword
		$str7 = "LwBFLmM.tmp         " fullword wide

		$com1 = "Invoke"
		$com2 = "GetCurrentProcess"

		$exp1 = "FileRipper"
		$exp2 = "InitGadgets"
		$exp3 = "Gadgets"

	condition:
		filesize < 7KB and all of ($str*) and (any of ($exp*) or all of ($com*)) and uint16be(0) == 0x4D5A and $ep at pe.entry_point
}

rule sidewinder_pdf_doc : APT_SideWinder {
	meta:
		version = "1.0"
		author = "Ebryx (Pvt.) Ltd."
		copyright = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detection of SideWinder's PDF Document in Corona-virus Campaign"

	strings:
		$str1 = "cftmo.exe"
		$str2 = "user-pc"

	condition:
		filesize <= 297KB and 2 of ($str*) and uint16be(0) == 0x4D5A
}
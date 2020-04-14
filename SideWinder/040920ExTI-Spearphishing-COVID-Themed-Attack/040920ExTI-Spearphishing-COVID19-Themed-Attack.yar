import "pe"

rule sidewinder_stage1_dropper : APT_SideWinder {
	meta:
		author = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects stage-1 javascript dropper"
		tlp = "Green"
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
		filesize >= 200KB and (1 of ($cnc*) and 2 of ($com*) and 3 of ($enum*))
}

rule sidewinder_linkzip_dll : APT_SideWinder {
	meta:
		author = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects LinkZip.dll exploit generator by James Forshaw"
		tlp = "Green"
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
		filesize < 10KB and (6 of ($str*)) and uint16be(0) == 0x4D5A
}

rule sidewinder_duser_dll : APT_SideWinder {
	meta:
		author = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects DUser.dll dropped by stage-1 javascript dropper"
		tlp = "Green"
	strings:
		$str1 = "$92d2f2dd-43d1-49a9-9ab5-b56ad3eb4af9"
		$str2 = "_CorDllMain"
		$str3 = "\\DUSER.dll"
		$str4 = "mscoree.dll"
		$str5 = "copytight @"
		$str6 = "System.Diagnostics" fullword
		$str7 = "LwBFLmM.tmp " fullword wide
		$com1 = "Invoke"
		$com2 = "GetCurrentProcess"
		$exp1 = "FileRipper"
		$exp2 = "InitGadgets"
		$exp3 = "Gadgets"
	condition:
		filesize < 7KB and 4 of ($str*) and (any of ($exp*) and all of ($com*)) and uint16be(0) == 0x4D5A
}

rule sidewinder_pdf_doc_spearphishing : APT_SideWinder {
	meta:
		author = "Ebryx DFIR"
		date = "09-04-2020"
		description = "Detects .lnk file sent in email containing the command to contact C2 domain"
		tlp = "Green"
	strings:
		$str1 = "cftmo.exe"
		$str2 = "user-pc"
	condition:
		filesize <= 300KB and 2 of ($str*) and uint16be(0) == 0x4D5A
}
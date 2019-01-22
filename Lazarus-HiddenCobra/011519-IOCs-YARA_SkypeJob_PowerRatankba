###15 Jan 2019
###Ebryx DFIR Team
###Latest IOCs of skypeJob malware dropper that serves the intrusion point for APT38/FashCash by Lazarus/HiddenCobra

import "pe"
rule SkypeJob_PowerRatankba_malware_dropper {
   meta:
      description = "SkypeJob_PowerRatankba malware dropper"
      author = "@VK_Intel"
      type = "experimental"
      date = "2019-01-15"
      hash1 = "f12db45c32bda3108adb8ae7363c342fdd5f10342945b115d830701f95c54fa9"
   strings:
      $f0 = "ThreadProc" fullword wide ascii
      $f1 = "SendUrl" fullword wide ascii
      $ps1 = "ps1" fullword wide ascii
      $b64 = "FromBase64String" fullword wide ascii
      $pdb = "F:\\05.GenereatePDF\\CardOffer\\salary\\salary\\obj\\Release\\ApplicationPDF.pdb" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
         filesize < 1000KB and
         pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
         ( $f0 and $f1 and $ps1 and #b64 > 2 )
      ) or ( all of them )
}

rule SkypeJob_PowerRatankba_malware_dropper_B {
   meta:
      description = "SkypeJob_PowerRatankba_malware_dropper_B"
      author = "@VK_Intel"
      date = "2019-01-15"
      hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"
   strings:
      $f0 = "function EncryptDES" fullword ascii
      $s0 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
      $s1 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
      $s2 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
      $s3 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
      $s4 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
      $s5 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
      $s6 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii
   condition:
      filesize < 500KB and $f0 and 2 of ($s*) 
}

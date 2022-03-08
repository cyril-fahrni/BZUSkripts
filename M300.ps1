#=========================================================================================#
# - By Mathis Oklé
# - Modul 300 Teil 2
# - 18.02.2022
#=========================================================================================#

#====================================[Poweshell Module]===================================#

Import-Module ActiveDirectory

#=======================================[Variabeln]=======================================#

$domain = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
$adroot_group = "G_Users"
$localroot_group = "L_Users"

$root_path = "C:\Shares\"
$austausch_path = $root_path+"Austausch"
$innendienst_path = $root_path+"Innendienst"
$innendienst_verträge_path = $root_path+"Innendienst\Verträge"
$innendienst_Briefe_path = $root_path+"Innendienst\Briefe"
$it_path = $root_path+"IT"
$it_Dokumentationen_path = $root_path+"IT\Dokumentationen"
$it_Listen_path = $root_path+"IT\Listen"
$personalapteilung_path = $root_path+"Personalabteilung"
$personalapteilung_Offene_Stellen_path = $root_path+"Personalabteilung\Offene Stellen"
$personalapteilung_Kündigungen_path = $root_path+"Personalabteilung\Kündigungen"
$personalapteilung_Zeugnisse_path = $root_path+"Personalabteilung\Zeugnisse"
$verkauf_path = $root_path+"Verkauf"
$verkauf_Offerten_path = $root_path+"Verkauf\Offerten"
$verkauf_Verträge_path = $root_path+"Verkauf\Verträge"

#===================================[Create Folder]=======================================#

New-Item -Path $austausch_path -ItemType Directory
New-Item -Path $innendienst_path -ItemType Directory
New-Item -Path $innendienst_verträge_path -ItemType Directory
New-Item -Path $innendienst_Briefe_path -ItemType Directory
New-Item -Path $it_path -ItemType Directory
New-Item -Path $it_Dokumentationen_path -ItemType Directory
New-Item -Path $it_Listen_path -ItemType Directory
New-Item -Path $personalapteilung_path -ItemType Directory
New-Item -Path $personalapteilung_Offene_Stellen_path -ItemType Directory
New-Item -Path $personalapteilung_Kündigungen_path -ItemType Directory
New-Item -Path $personalapteilung_Zeugnisse_path -ItemType Directory
New-Item -Path $verkauf_path -ItemType Directory
New-Item -Path $verkauf_Offerten_path -ItemType Directory
New-Item -Path $verkauf_Verträge_path -ItemType Directory



#=====================[Create Groups and Permissions]=======================================#
$shares = Get-ChildItem -Path C:\Shares -Recurse -Directory -Force -ErrorAction SilentlyContinue | Select-Object  -ExpandProperty Fullname

foreach ($share in $shares){
$sharepath = $share
$share = $share.Remove(0,2)
[Regex]::Escape($share)
$share = $share -replace("\\","_")
$share = $share -replace(" ","_")

$adgroupname_RW = $adroot_group+$share+"_RW"
$adgroupname_R = $adroot_group+$share+"_R"

New-ADGroup -Name $adgroupname_RW -GroupCategory Security -GroupScope Global
New-ADGroup -Name $adgroupname_R -GroupCategory Security -GroupScope Global

$localgroupname_RW = $localroot_group+$share+"_RW"
$localgroupname_R = $localroot_group+$share+"_R"

New-LocalGroup -Name $localgroupname_RW 
New-LocalGroup -Name $localgroupname_R 

Add-ADGroupMember -Identity $localgroupname_RW -Members $adgroupname_RW
Add-ADGroupMember -Identity $localgroupname_R -Members $adgroupname_R

#Set RW Permisson on Folder
$ACL = Get-ACL -Path $sharepath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($localgroupname_RW,"Write","Allow")
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $sharepath
(Get-ACL -Path $sharepath).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

#Set RW Permisson on Folder
$ACL = Get-ACL -Path $sharepath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($localgroupname_R,"Readandexecute","Allow")
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path $sharepath
(Get-ACL -Path $sharepath).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize


New-SmbShare -Name "Shares" -Path $root_path
}



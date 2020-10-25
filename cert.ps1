#- https://stackoverflow.com/questions/43799755/export-certificate-with-private-key-including-all-certificates-in-path-using-pow

# Script to export certificate from LocalMachine store along with private key
$Password = "."; #password to access certificate after exporting
$UserName = "test"; # name of the certificate to export
$DestCertName="efs";
$ExportPathRoot = "C:\Users\test\Documents"

Write-Output $UserName

$CertListToExport = Get-ChildItem -Path cert:\CurrentUser\My | ?{ $_.Subject -Like "*CN=$UserName*" }

foreach($CertToExport in $CertListToExport | Sort-Object Subject)
{
    # Destination Certificate Name should be CN. 
    # Since subject contains CN, OU and other information,
    # extract only upto the next comma (,)
    #$DestCertName=$CertToExport.Subject.ToString().Replace("CN=","");
   # $DestCertName = $DestCertName.Substring(0, $DestCertName.IndexOf(","));

    $CertDestPath = Join-Path -Path $ExportPathRoot -ChildPath "$DestCertName.pfx"

    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

    # Export PFX certificate along with private key
    Export-PfxCertificate -Cert $CertToExport -FilePath $CertDestPath -Password $SecurePassword -Verbose
}
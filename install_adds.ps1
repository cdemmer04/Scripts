param(
    [String]
    $domainName = "domain.local"
)

# Set variables
$passwd = ConvertTo-SecureString -AsPlainText "Pa55w.rd" -Force

Write-Host $domainName
# Install management tools for adds
# Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

# # Set up adds domain
# Install-ADDSForest -DomainName $domainName -SafeModeAdministratorPassword $passwd -InstallDns -Force
# Disable unnecessary Windows services for PoC virtual machines
# Author: Chiel Demmer

# Windows Update
Stop-Service -Name "wuauserv"
Set-Service -Name "wuauserv" -StartupType Disabled

# Themes
Stop-Service -Name "themes"
Set-Service -Name "themes" -StartupType Disabled

# Prefetch
Stop-Service -Name "sysmain"
Set-Service -Name "sysmain" -StartupType Disabled

# Printspooler
Stop-Service -Name "spooler"
Set-Service -Name "spooler" -StartupType Disabled

Stop-Service -Name "sharedaccess"
Set-Service -Name "sharedaccess" -StartupType Disabled

# IP Helper
Stop-Service -Name "iphlpsvc"
Set-Service -Name "iphlpsvc" -StartupType Disabled

# Disk optimizer / defrag
Stop-Service -Name "defragsvc"
Set-Service -Name "defragsvc" -StartupType Disabled

# Audio
Stop-Service -Name "audiosrv"
Set-Service -Name "audiosrv" -StartupType Disabled

# Stop-Service -Name "browser"
# Set-Service -Name "browser" -StartupType Disabled

# Windows Search
Stop-Service -Name "WSearch"
Set-Service -Name "WSearch" -StartupType Disabled
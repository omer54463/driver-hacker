param (
    [parameter(HelpMessage = "Python executable path")]
    [string] $Python = "py",
    [parameter(HelpMessage = "Perform an editable installation")]
    [switch] $Development
)

function Format-InstallCommand {
    param (
        [parameter(Mandatory)]
        [string] $Python,
        [switch] $Development,
        [parameter(ValueFromPipeline)]
        [string] $Package
    )

    begin {
        $Command = "$Python -m pip install"
    }

    process {
        $Command = $Development ? "$Command -e $Package" : "$Command $Package"
    }

    end {
        $Development ? "$Command --config-settings editable_mode=compat" : $Command
    }
}

function Install-Checkers {
    param (
        [parameter(Mandatory)]
        [string] $Python
    )

    $Checkers = @("mypy", "ruff")
    $InstallCheckersCommand = $Checkers | Format-InstallCommand -Python $Python
    Invoke-Expression -Command $InstallCheckersCommand
}

function Install-Packages {
    param (
        [parameter(Mandatory)]
        [string] $Python,
        [switch] $Development
    )

    $Packages = @(".\driver-hacker")
    $InstallPackagesCommand = $Packages | Format-InstallCommand -Python $Python -Development:$Development
    Invoke-Expression -Command $InstallPackagesCommand
}

Install-Packages -Python $Python -Development:$Development

if ($Development) {
    Install-Checkers -Python $Python
}

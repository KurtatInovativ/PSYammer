$Global:YammerBaseUri = 'https://www.yammer.com/api/v1'
$Global:YammerUserUri = '{0}/{1}' -f $Global:YammerBaseUri, 'users.json'
$Global:YammerGroupUri = '{0}/{1}' -f $Global:YammerBaseUri, 'groups.json'
#$Global:YammerSearchUri = '{0}/{1}' -f $Global:YammerBaseUri, 'autocomplete/ranked?prefix='
$Global:YammerUserTokenUri = '{0}/{1}' -f $Global:YammerBaseUri, 'oauth/tokens.json'
$Global:YammerGroupMembershipUri = '{0}/{1}' -f $Global:YammerBaseUri, 'group_memberships.json?group_id='
$Global:ClientId = $null
$Global:AdminToken = $null


function Connect-Yammer {
	<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
	[cmdletbinding(DefaultParameterSetName='Client')]
	param(
		[Parameter( ParameterSetName='Client',
					Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$AdminToken,
		[Parameter( ParameterSetName='Client',
					Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$ClientId,
		[Parameter( ParameterSetName='Connection',
					Mandatory=$true)]
		[Alias('YammerConnection')]
		[ValidateNotNullOrEmpty()]
		[PSObject]$Connection
	)

	if($PSCmdlet.ParameterSetName -eq 'Connection') {
		$Global:AdminToken = $Connection.AdminToken
		$Global:ClientId = $Connection.ClientId
	}
	else {
		$Global:AdminToken = $AdminToken
		$Global:ClientId = $ClientId
	}
}

function Get-YammerGroup {
	<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
	[Outputtype('PSCustomObject')]
	param (
		[Parameter( ValueFromPipelineByPropertyName=$true, 
				    ValueFromPipeline=$true,
				    Position=0)]
		[Alias('GroupName')]
		[string]$Name,
		[int]$ReturnCount = 99
	)

	Begin {
		if (!($Global:AdminToken)){
			Throw 'Use Connect-Yammer to authenticate before using this function'
		}
		$Headers  = @{
            "Accept" = "*/*"
            "Authorization" = "Bearer "+$Global:AdminToken
            "accept-encoding" = "gzip"
            "content-type" = "application/json"
        }
	}

	Process {
		if($Name) {
			#$GroupUri = '{0}{1}&models=group:{2}' -f $Global:YammerSearchUri,$Name,$ReturnCount
            $GroupUri = '{0}?letter={1}' -f $Global:YammerGroupUri, $Name 
		}
		else {
			$GroupUri = $Global:YammerGroupUri
		}
		$GroupJson = Invoke-WebRequest -Uri $GroupUri -Method Get -Headers $Headers
		$Groups = ConvertFrom-Json -InputObject $GroupJson 
        
        $defaultProperties = @('Name','Id','Description')
	    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultProperties)
	    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
	    
        foreach ($group in $groups) {
          
          $CustomGroup = $null  
          $CustomGroup = [PSCustomObject]@{
                Id = $group.id
                Name = $group.Name
                Description = $group.description
                Email = $group.email
                Privacy = $group.privacy
                Url = $group.url
                Created = [datetime]($group.created_at)
                Public = $group.external
                State = $group.state
                Moderated = $group.moderated
                Visible = $group.show_in_directory
          }#EndPSCustomObject
          $CustomGroup.PSObject.TypeNames.Insert(0,'Yammer.Group')
          Add-Member -InputObject $CustomGroup -MemberType 'MemberSet' -Name 'PSStandardMembers' -Value $PSStandardMembers
          
          $CustomGroup
        }

	}
}

function GetYammerUserToken {
	<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias('UserUPN')]
		[Alias('UserPrincipalName')]
		[string]$User
	)
	Begin {

		if(!($Global:AdminToken) -or !($Global:ClientId)) {
			Throw 'Use Connect-Yammer to authenticate before using this function'
		}

		Write-verbose 'validating if a UPN is provided'
		if($User -notmatch "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?") {
			Throw 'please specify a valid UPN'
		}
		# Request Headers
	    $Headers = @{
        "Accept" = "*/*"
        "Authorization" = "Bearer "+ $Global:AdminToken
        "accept-encoding" = "gzip"
        "content-type"="application/json"
		}
	}
	Process {
		# Get Yammer user token
		$YammerUsersJson = (Invoke-WebRequest -Uri $Global:YammerUserUri -Method Get -Headers $Headers)
 		$YammerUsers = $YammerUsersJson | ConvertFrom-Json
		foreach ($YammerUser in $YammerUsers)
		{
			if ($YammerUser.email -eq $User)
			{
				$YammerUserId = $YammerUser.id
			}
		}
			$UserTokenUri = '{0}?user_id={1}&consumer_key={2}' -f $Global:YammerUserTokenUri, $YammerUserId, $Global:ClientId
			$UserToken = (Invoke-WebRequest -Uri $UserTokenUri -Method Get -Headers $Headers).content | ConvertFrom-Json
			$CustomUserToken = $UserToken.token
			$CustomUserToken
	}
	
	
}

function Add-YammerGroupMember {
	<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
	[cmdletbinding()]
	param(
		$User,
		$Group
	)
	$UserToken = GetYammerUserToken -User $User
	$Headers = @{
        "Accept" = "*/*"
        "Authorization" = "Bearer "+$UserToken
        "accept-encoding" = "gzip"
        "content-type" = "application/json"
    }
	#get the group
	$Group = Get-YammerGroup -Name $group
	$AddGroupMembershipUri = '{0}{1}' -f $Global:YammerGroupMembershipUri, $Groups.Id
    $Result = Invoke-WebRequest -Uri $AddGroupMembershipUri -Method Post -Headers $Headers }

function New-YammerGroup {	
	<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[switch]$Private = $true
	)
	Begin {
		if(!($Global:AdminToken)) {
			Throw 'Use Connect-Yammer to authenticate before using this function'
		}
		# Request Headers
	    $Headers = @{
        "Accept" = "*/*"
        "Authorization" = "Bearer "+ $Global:AdminToken
        "accept-encoding" = "gzip"
        "content-type"="application/json"
		}
	}

	Process {
		#check if group exists
		$group = Get-YammerGroup -Name $Name
		if($group.Name -eq $Name) {
			Write-error "Group $Name already exists"
		}
		else {
			#create the group
			$groupUri = '{0}?name={1}&private={2}' -f $Global:YammerGroupUri, $Name, $Private
			$result = Invoke-WebRequest -Uri $groupUri -Method Post -Headers $Headers
			$Group = ConvertFrom-Json -InputObject $result

			if ($group) {
				$CustomGroup = $null  
				$CustomGroup = [PSCustomObject]@{
					Id = $group.id
					Name = $group.Name
					Description = $group.description
					Email = $group.email
					Privacy = $group.privacy
					Url = $group.url
					Created = [datetime]($group.created_at)
					Public = $group.external
					State = $group.state
					Moderated = $group.moderated
					Visible = $group.show_in_directory
				}#EndPSCustomObject
				$CustomGroup.PSObject.TypeNames.Insert(0,'Yammer.Group')
				Add-Member -InputObject $CustomGroup -MemberType 'MemberSet' -Name 'PSStandardMembers' -Value $PSStandardMembers
				$CustomGroup
			}
		}
	}
}


#region Handle Module Removal
$ExecutionContext.SessionState.Module.OnRemove ={
    Remove-Variable YammerBaseUri -Scope Global -Force
    Remove-Variable YammerUserUri -Scope Global -Force
    Remove-Variable YammerGroupUri -Scope Global -Force
    Remove-Variable YammerGroupMembershipUri -Scope Global -Force
    Remove-Variable ClientId -Scope Global -Force
	Remove-Variable AdminToken -Scope Global -Force
}
#endregion Handle Module Removal
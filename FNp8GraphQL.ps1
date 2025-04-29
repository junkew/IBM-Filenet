#Simple powershell 5.1 example GraphQL with userid/password
clear-host
# Define endpoint
$uri = "https://cpd-cp4ba-starter.apps.<name>.techzone.ibm.com/content-services-graphql/graphql"

# Ensure TLS 1.2 is used (required for most secure endpoints)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set username and password
$username = "<yourusername>"
$password = "<yourpassword>"

# Encode credentials for Basic Auth
$pair = "$username`:$password"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [Convert]::ToBase64String($bytes)

# Set headers
$headers = @{
    "Authorization" = "Basic $base64"
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

# Define GraphQL query (example: list repositories)
# Minimal GraphQL query that MUST return data
$body = @{
    query = "{ domain { name } }"
} | ConvertTo-Json -Compress

$body = @{
    query = "{  domain {    objectStores {      objectStores {        symbolicName      }    }  }}"
}| ConvertTo-Json -Compress

# Send POST request
$response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body

# Display result
$response | convertto-json -depth 5

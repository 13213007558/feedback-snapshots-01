# Simulated platform request records

Every GET the recording router observed, in chronological order.

## Request 1
- endpoint: `http://broad-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "machine-shared-system-assigned-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `no (pre-challenge 401)`

## Request 2
- endpoint: `http://broad-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "machine-shared-system-assigned-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `yes`

## Request 3
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `no (pre-challenge 401)`

## Request 4
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `yes`

## Request 5
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `no (pre-challenge 401)`

## Request 6
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `yes`

## Request 7
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `no (pre-challenge 401)`

## Request 8
- endpoint: `http://approved-platform.example/metadata/identity/oauth2/token`
- params: `{"api-version": "2020-06-01", "client_id": "approved-user-assigned-client-id", "resource": "https://target-resource.example"}`
- sent Authorization header: `yes`

import requests

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"

class AuthClient:
    def __init__(self, client_id, client_secret, oidc_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oidc_url = oidc_url

        self.introspect_url = self.oidc_url + f"/introspect"
        self.token_url = self.oidc_url + f"/token"
        self.register_url = self.oidc_url + f"/register"

        self.basic_auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)

    def is_token_valid(self, token):
        body = {
            "token": token
        }

        response = requests.post(self.introspect_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to validate the access token: " + response.text)

        token_info = response.json()

        if token_info["active"]:
            return True
        
        return False
    
    def exchange_access_token(self, token, grant_type, scopes, audience=None):
        body = {
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": " ".join(scopes),
            "grant_type": grant_type
        }

        if audience:
            body["audience"] = audience

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to exchange access token: " + response.text)

        return response.json()["access_token"]
    
    def register_client(self, access_token, client_name, resource_ids, scopes):
        body = {
            "client_name": client_name,
            "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": scopes,
            "resourceIds": resource_ids
        }

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.post(self.register_url, json=body, headers=headers)

        if response.status_code != 201:
            raise Exception("Failed to register a new client: " + response.text)

        response_data = response.json()
        
        return {
            "client_id": response_data["clientId"],
            "client_secret": response_data["clientSecret"]
        }

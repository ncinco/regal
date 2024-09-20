package asb.synapse.apiservice.standardpolicy

import input.attributes.request.http as http_request
import rego.v1

default allow := false

allow if {
    print("Checking Identity JWT from Authorization Header")
    identity_jwt_signature_and_lifetime_valid
    issuer_specific_claims_valid
    print("Identity JWT is valid")
}

get_public_key_scopes(splitclientcertarray) := "policyinformationpointjwt" if {
    splitclientcertarray[_] == "By=kuma://asb-pip-service/true"
} else := "meshidentityjwt"

identityjwt := {"valid": valid, "header": header, "payload": payload} if {
    print("Extracting JWT from Authorization Header")
    authorization_header := http_request.headers.authorization
    startswith(authorization_header, "Bearer ")
    token := substring(http_request.headers.authorization, count("Bearer "), -1)
    token != ""

    print("Extracted JWT from Authorization Header. Obtaining Public Key Scopes")

    public_key_scopes := get_public_key_scopes(split(http_request.headers["x-forwarded-client-cert"], ";"))

    jwks_url := sprintf("http://127.0.0.1:4000/jwks?scope=%s", [public_key_scopes])

    jwks_response := http.send({
        "method": "GET",
        "url": jwks_url
    })
    jwks_response.status_code == 200

    print("Obtained Public Key Scopes. Decoding JWT")

    [header, payload, _] := io.jwt.decode(token)

    print("Decoded JWT. Validating JWT Signature")

    valid := io.jwt.verify_rs256(token, jwks_response.raw_body)

    print("JWT Signature Valid: ", valid)
}

issuer_specific_claims_valid if {
    print("checking the kong gateway issuer")
    identityjwt.payload.iss == "baas-kong-gateway"
}

issuer_specific_claims_valid if {
    print("checking the entra issuer and role")
    identityjwt.payload.iss == "htts://sts.windows.net/5cb9fead-916c-4e06-b693-1a224ecb6412"
    "PolicyInformationCaller" in identityjwt.payload.roles
}

identity_jwt_signature_and_lifetime_valid if {
    print("checking if the identity jwt is valid")
    identityjwt.valid
    now := time.now_ns() / 1000000000
    # identityjwt.payload.nbf -5 <= now
    print("checking the expiry date")
    now < identityjwt.payload.exp + 5
}

identity_jwt_is_partner_identity if {
    identityjwt.payload["asb.oath.clientId"]
    not identityjwt.payload["asb.iam.identity.asbCustomerNumber"]
}

identity_jwt_is_delegated_auth if {
    identityjwt.payload["asb.oath.clientId"]
    identityjwt.payload["asb.iam.identity.asbCustomerNumber"]
}

identity_jwt_is_ids_identity if {
    not identityjwt.payload["asb.oath.clientId"]
    identityjwt.payload["asb.iam.identity.asbCustomerNumber"]
}
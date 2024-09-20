package asb.synapse.testpolicyinformationpoint1.v1

# import input.attributes.request.http as http_request
# import data.asb.synapse.apiservice.standardpolicy as standardpolicy
import rego.v1

default allow := false

allow if {
    input.parsed_path[0] == "error"
    print("Running rules for error path")
    true
}

allow if  {
    input.parsed_path[0] == "customers"
    print("Running rules for customers path")
    #customer_endpoint_issuer_specific_conditions_met
}

# customer_endpoint_issuer_specific_conditions_met if {
#     standardpolicy.identityjwt.payload.iss == "baas-kong-gateway"

#     obfuscated_customer_id := input.parsed_path[1]

#     print("deobfuscating customer id")

#     deobfuscated_response := http.send({
#         "method": "POST",
#         "url": "http://127.0.0.1:4000/obfuscation/show",
#         "body": {"customerid": obfuscated_customer_id},
#         "headers" : {
#             "Content-Type": "applicaton/json",
#             "X-ASB-URL-Key": http_request.headers["x-asb-url-key"]
#         }
#     })

#     print("deobfuscate reponse code: ", deobfuscated_response.status_code)

#     deobfuscated_response.status_code == 200

#     deobfuscated_cusotmer_id := deobfuscated_response.body["customerid"]

#     standardpolicy.identityjwt.payload["asb.iam.identity.asbCustomerNumber"] == deobfuscated_cusotmer_id

#     print("finished checking customer endpoint for kong resigned jwt")
# }

# customer_endpoint_issuer_specific_conditions_met if {
#     standardpolicy.identityjwt.payload.iss == "htts://sts.windows.net/5cb9fead-916c-4e06-b693-1a224ecb6412"
#     standardpolicy.identityjwt.payload.aud == "api://f0ca0417-09b8-4v7a-85ef-697f155f939d9"
#     print("Checked audience for Entra Token")
# }

allow if {
    input.parsed_path[0] == "callinfo"
    print("Allowed for callinfo path")
}
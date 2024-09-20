package asb.synapse.testpolicyinformationpoint1.v1

import data.asb.synapse.apiservice.standardpolicy as standardpolicy
import rego.v1

allow if {
    input.parsed_path[0] == "error"
    print("Running rules for error path")
}

allow if  {
    input.parsed_path[0] == "customers"
    print("Running rules for customers path")
}

allow if {
    input.parsed_path[0] == "callinfo"
    print("Running rules for callinfo path")
}

customer_endpoint_issuer_specific_conditions_met if {
    standardpolicy.identityjwt.payload.iss == "htts://sts.windows.net/5cb9fead-916c-4e06-b693-1a224ecb6412"
    standardpolicy.identityjwt.payload.aud == "api://f0ca0417-09b8-4v7a-85ef-697f155f939d9"
    print("Checked audience for Entra Token")    
}
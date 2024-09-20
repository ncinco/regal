package asb.synapse.testpolicyinformationpoint1.v1_test

import data.asb.synapse.testpolicyinformationpoint1.v1 as testpolicyinformationpoint1
import rego.v1

test_error_allowed if {
	testpolicyinformationpoint1.allow with input as {
        "parsed_path": ["error"]
    }
}

test_customers_allowed if {
	testpolicyinformationpoint1.allow with input as {
        "parsed_path": ["customers"]
    }
}

test_callinfo_allowed if {
	testpolicyinformationpoint1.allow with input as {
        "parsed_path": ["callinfo"]
    }
}

test_customer_endpoint_issuer_specific_conditions_met_baas_kong_gateway if {
    input_test := {
        "parsed_path": ["callinfo", "some customer id"],
        "attributes" : {
            "request" : {
                "http" : {
                    "headers" : {
                        "authorization" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJncm91cHMiOlsidGVzdGVycyJdfQ.2eoq7A3vj7KIAlrPZnHDS4VfAQIyfblkPImzTIk0PtA",
                        "x-forwarded-client-cert" : "By=kuma://asb-pip-service/true",
                        "x-asb-url-key": ""
                    }
                }
            }
        }
    }

    mock_http_send := {
        "status_code" : 200,
        "raw_body": "raw_body",
        "body" : {
            "customerid" : "some customer id"
        }
    }

    jwt_header := {}

    jwt_payload := {
        "iss" : "baas-kong-gateway",
        "aud" : "api://f0ca0417-09b8-4v7a-85ef-697f155f939d9",
        "asb.iam.identity.asbCustomerNumber" : "some customer id"
    }

    jwt_sig := {}

    mock_io_jwt_decode := [jwt_header, jwt_payload, jwt_sig]
    mock_io_jwt_verify_rs256 := true

    testpolicyinformationpoint1.customer_endpoint_issuer_specific_conditions_met with input as input_test
        with http.send as mock_http_send
        with io.jwt.decode as mock_io_jwt_decode
        with io.jwt.verify_rs256 as mock_io_jwt_verify_rs256 
}

test_customer_endpoint_issuer_specific_conditions_met_entra_id if {
    input_test := {
        "attributes" : {
            "request" : {
                "http" : {
                    "headers" : {
                        "authorization" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJncm91cHMiOlsidGVzdGVycyJdfQ.2eoq7A3vj7KIAlrPZnHDS4VfAQIyfblkPImzTIk0PtA",
                        "x-forwarded-client-cert" : "By=kuma://asb-pip-service/true"
                    }
                }
            }
        }
    }

    mock_http_send := {
        "status_code" : 200,
        "raw_body" : "raw_body"
    }

    jwt_header := {}

    jwt_payload := {
        "iss" : "htts://sts.windows.net/5cb9fead-916c-4e06-b693-1a224ecb6412",
        "aud" : "api://f0ca0417-09b8-4v7a-85ef-697f155f939d9"
    }

    jwt_sig := {}

    mock_io_jwt_decode := [jwt_header, jwt_payload, jwt_sig]
    mock_io_jwt_verify_rs256 := true

    testpolicyinformationpoint1.customer_endpoint_issuer_specific_conditions_met with input as input_test
        with http.send as mock_http_send
        with io.jwt.decode as mock_io_jwt_decode
        with io.jwt.verify_rs256 as mock_io_jwt_verify_rs256 
}
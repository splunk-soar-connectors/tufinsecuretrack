# File: tufinsecuretrack_consts.py
# Copyright (c) 2017-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

TUFINSECURETRACK_CONFIG_URL = "url"
TUFINSECURETRACK_CONFIG_USERNAME = "username"
TUFINSECURETRACK_CONFIG_PASSWORD = "password"
TUFINSECURETRACK_CONFIG_VERIFY_SSL = "verify_server_cert"
TUFINSECURETRACK_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
TUFINSECURETRACK_EXCEPTION_OCCURRED = "Exception occurred"
TUFINSECURETRACK_ERR_SERVER_CONNECTION = "Connection failed"
TUFINSECURETRACK_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
TUFINSECURETRACK_ERR_FROM_SERVER = "API failed.\nStatus code: {status}\nDetail: {detail}"
TUFINSECURETRACK_REST_RESPONSE = "response"
TUFINSECURETRACK_REST_RESP_OTHER_ERROR_MSG = "Error returned"
TUFINSECURETRACK_REST_RESP_SUCCESS = 200
TUFINSECURETRACK_REST_RESP_BAD_REQUEST = 400
TUFINSECURETRACK_REST_RESP_BAD_REQUEST_MSG = "Parameters are invalid"
TUFINSECURETRACK_REST_RESP_UNAUTHORIZED = 401
TUFINSECURETRACK_REST_RESP_UNAUTHORIZED_MSG = "User is not permitted to access"
TUFINSECURETRACK_REST_RESP_FORBIDDEN = 403
TUFINSECURETRACK_REST_RESP_FORBIDDEN_MSG = "Forbidden."
TUFINSECURETRACK_REST_RESP_NOT_FOUND = 404
TUFINSECURETRACK_REST_RESP_NOT_FOUND_MSG = "Resource not found."
TUFINSECURETRACK_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
TUFINSECURETRACK_TEST_CONNECTIVITY_FAIL = "Connectivity test failed"
TUFINSECURETRACK_TEST_CONNECTIVITY_PASS = "Connectivity test succeeded"
TUFINSECURETRACK_JSON_IP_ADDRESS = "ip"
TUFINSECURETRACK_IP_VALIDATION_FAILED = "parameter 'ip_address' validation failed"
TUFINSECURETRACK_TEST_CONNECTIVITY_ENDPOINT = "/securetrack/api/network_objects/search"
TUFINSECURETRACK_NETWORK_OBJECT_ENDPOINT = "/securetrack/api/network_objects/search.json"
TUFINSECURETRACK_NETWORK_RULES_ENDPOINT = "/securetrack/api/network_objects/{id}/rules.json"
TUFINSECURETRACK_JSON_INVALID_IP_ADDRESS = "No network object found for specified IP address"
TUFINSECURETRACK_JSON_SOURCE_IP_ADDRESS = "source_ip"
TUFINSECURETRACK_JSON_DESTINATION_IP_ADDRESS = "destination_ip"
TUFINSECURETRACK_JSON_PROTOCOL = "protocol"
TUFINSECURETRACK_JSON_PORT = "port"
TUFINSECURETRACK_UNEXPECTED_RESPONSE = "Expected response not found"
TUFINSECURETRACK_NO_FIREWALL_RULE_CONFIGURED = "No matching rule found"
TUFINSECURETRACK_MATCHING_RULE_ENDPOINT = "/securetrack/api/policy_analysis/query/matching_rules.json"
TUFINSECURETRACK_MANDATORY_IP_PARAM = "One of the 'source_ip' or 'destination_ip' parameters need to be specified"

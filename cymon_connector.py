# File: cymon_connector.py
#
# Copyright (c) 2016-2019 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from cymon_consts import *

# Required library imports
import json
import requests
import ipaddress


class CymonConnector(BaseConnector):
    # Actions supported by this app
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_DOMAIN_LOOKUP = "lookup_domain"
    ACTION_ID_LOOKUP_URL = "lookup_url"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_connectivity"
    ACTION_ID_FILE_REPUTATION = "file_reputation"

    def __init__(self):

        super(CymonConnector, self).__init__()

    def initialize(self):

        config = self.get_config()

        self._api_key = config.get(CYMON_CONFIG_API_KEY, None)

        self._headers = {}

        if (not self._api_key):
            return phantom.APP_SUCCESS

        self._headers = {
            'Authorization': 'Token {0}'.format(self._api_key)
        }

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint):

        full_url = CYMON_BASE_API_URL + endpoint

        headers = self._headers

        params = {'limit': 1000}
        try:
            r = requests.get(full_url, headers=headers, params=params)
        except Exception as e:
            return (phantom.APP_ERROR, "Could not complete rest call. {}".format(e))

        if (r.status_code == 404):
            return (phantom.APP_SUCCESS, None)

        try:
            resp_json = r.json()
        except Exception as e:
            return (phantom.APP_ERROR, "Could not convert response to JSON. {}".format(e))

        if (400 < r.status_code):
            return (phantom.APP_ERROR, "Response failed. {}".format(resp_json))

        return (phantom.APP_SUCCESS, resp_json)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(unicode(ip_address_input))
        except:
            return False

        return True

    def _ip_reputation(self, params):
        '''
        Conducts an "IP Reputation" call.  Finds related events, domains, urls.
        Requires 4 rest calls.  Oh well.

        :param params:
        :return:
        '''
        action_result = self.add_action_result(ActionResult(params))

        ip = params[CYMON_JSON_IP]

        endpoint = CYMON_API_URI_IP_EVENTS.format(addr=ip)
        ret_val, response = self._make_rest_call(endpoint)
        total_count = 0
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Rest call failed", response)
        if response:
            action_result.add_data({'events': response})
            total_count += response['count']

        endpoint = CYMON_API_URI_IP_DOMAINS.format(addr=ip)
        ret_val, response = self._make_rest_call(endpoint)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Rest call failed", response)
        if response:
            action_result.add_data({'domains': response})
            total_count += response['count']

        endpoint = CYMON_API_URI_IP_URLS.format(addr=ip)
        ret_val, response = self._make_rest_call(endpoint)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Rest call failed", response)
        if response:
            action_result.add_data({'urls': response})
            total_count += response['count']

        action_result.set_summary({'total_count': total_count})

        return action_result.set_status(phantom.APP_SUCCESS, "IP Reputation succeeded")

    def _file_reputation(self, params):

        action_result = self.add_action_result(ActionResult(params))

        hash = params[CYMON_JSON_HASH]

        endpoint = CYMON_API_URI_FILE_REPUTATION.format(hash=hash)

        ret_val, response = self._make_rest_call(endpoint)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Rest call failed", response)
        total_count = 0
        if response:
            action_result.add_data(response)
            total_count += response['count']

        action_result.set_summary({'total_count': total_count})
        return action_result.set_status(phantom.APP_SUCCESS, "File reputation succeeded")

    def _lookup_domain(self, params):

        action_result = self.add_action_result(ActionResult(params))

        domain = params[CYMON_JSON_DOMAIN]

        endpoint = CYMON_API_URI_DOMAIN_LOOKUP.format(name=domain)

        ret_val, response = self._make_rest_call(endpoint)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Rest call failed", response)
        if response:
            action_result.add_data(response)
            if 'ips' in response:
                temp_ips = []
                for link in response['ips']:
                    temp_ips.append(link.replace(
                        "https://cymon.io/api/nexus/v1/ip/", ""))
                response['ips'] = temp_ips
        else:
            action_result.set_summary({"domain_count": 0})

        return action_result.set_status(phantom.APP_SUCCESS, "Lookup Domain succeeded")

    def _test_connectivity(self):

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES,
                           "Querying Cymon API looking up 8.8.8.8")

        # set the endpoint
        endpoint = CYMON_API_URI_IP_LOOKUP.format(addr="8.8.8.8")

        # Action result to represent the call
        action_result = ActionResult()

        # Progress message, since it is test connectivity, it pays to be verbose
        self.save_progress("Using endpoint {0}".format(endpoint))

        # Make the rest endpoint call
        ret_val, response = self._make_rest_call(endpoint)

        # Process errors
        if (phantom.is_fail(ret_val)):
            # Dump error messages in the log
            self.debug_print(action_result.get_message())

            # Set the status of the complete connector result
            self.set_status(phantom.APP_ERROR, action_result.get_message())

            # Append the message to display
            self.append_to_message(response)

            # return error
            return phantom.APP_ERROR

        # Set the status of the connector result
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Test Connectivity succeeded")

    def handle_action(self, params):

        # Gets the action identifier from BaseConnector's handle_action
        action = self.get_action_identifier()

        # ret_val is initialized as success, so that if no action is found, it still succeeds
        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_IP_REPUTATION):
            ret_val = self._ip_reputation(params)
        elif (action == self.ACTION_ID_DOMAIN_LOOKUP):
            ret_val = self._lookup_domain(params)
        elif (action == self.ACTION_ID_FILE_REPUTATION):
            ret_val = self._file_reputation(params)
        elif (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url,
                               verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CymonConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

# File: illumio_connector.py
#
# Copyright (c) 2022 Illumio.
#
# This unpublished material is proprietary to Illumio.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Illumio.
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


# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector

from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import requests
import json
import illumio
from datetime import datetime
from dateutil.parser import parse
import pytz

from illumio.exceptions import IllumioException


class IllumioConnector(BaseConnector):
    """
    Represent a connector module that implements the actions that are provided by the app.

    IllumioConnector is a class that is derived from the BaseConnector class.
    """

    def __init__(self):
        """Initialize global variables."""
        # Call the BaseConnectors init first
        super(IllumioConnector, self).__init__()

        self._state = None
        self._api_key = None
        self._api_secret = None
        self._hostname = None
        self._port = None
        self._org_id = None

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to PCE")

        if self.connect_pce():
            self.save_progress("Connectivity Test Passed")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Connectivity Test Failed")
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_get_traffic_analysis(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, end_time = self.convert_to_iso(
            param["end_time"], action_result, "end_time"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, start_time = self.convert_to_iso(
            param["start_time"], action_result, "start_time"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if self.check_starttime_greater_than_endtime(start_time, end_time):
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'end_time' parameter must be greater than 'start_time' parameter",
            )

        port = self._validate_integers(self, param["port"], "port")
        if self._port is None:
            return self.get_status()

        if port <= 0 or port >= 65536:
            return action_result.set_status(
                phantom.APP_ERROR, "Please enter a valid value for 'port' parameter"
            )

        protocol = param["protocol"].lower()
        if protocol not in ["tcp", "udp"]:
            return action_result.set_status(
                phantom.APP_ERROR, "Please enter a valid value for 'protocol' parameter"
            )

        policy_decisions_string = param["policy_decisions"].lower()

        pce = self.connect_pce()
        if not pce:
            return action_result.set_status(
                phantom.APP_ERROR, "Failed to connect to PCE"
            )

        try:
            policy_decisions_list = [
                x.strip() for x in policy_decisions_string.split(",")
            ]
            policy_decisions_list = list(filter(None, policy_decisions_list))

            traffic_query = illumio.TrafficQuery.build(
                start_date=start_time.isoformat(),
                end_date=end_time.isoformat(),
                include_services=[{"port": port, "proto": protocol}],
                policy_decisions=policy_decisions_list,
            )

            traffic_flow_list = pce.get_traffic_flows_async(
                query_name="phantom_block_port_traffic_query",
                traffic_query=traffic_query,
            )

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR, f"Encountered error while running traffic query: {e}"
            )

        traffic_list_length = len(traffic_flow_list)

        self.debug_print(
            f"Found {traffic_list_length} records for the specified time range"
        )

        result = {
            "traffic_flow": [
                self.convert_object_to_json(flow) for flow in traffic_flow_list
            ]
        }
        action_result.add_data(result)
        if traffic_list_length == 0:
            return action_result.set_status(
                phantom.APP_SUCCESS, "No traffic found for the specified time range"
            )
        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully fetched traffic flow list"
        )

    def handle_action(self, param):
        """
        Get current action identifier and call member function of its own to handle the action.
        """
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "get_traffic_analysis":
            ret_val = self._handle_get_traffic_analysis(param)

        return ret_val

    def initialize(self):
        """Initialize the global variables with its value and validate it."""
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        # get the asset config
        config = self.get_config()
        self._api_key = config["api_key"]
        self._api_secret = config["api_secret"]
        self._hostname = config["hostname"]

        self._port = self._validate_integers(self, config["port"], "port")
        if self._port is None:
            return self.get_status()

        self._org_id = self._validate_integers(self, config["org_id"], "org_id")
        if self._org_id is None:
            return self.get_status()

        return phantom.APP_SUCCESS

    def check_for_future_datetime(self, datetime_obj):
        """
        Checks the given datetime str isa future date or not

        :param datetime_obj: datetime object
        :return : bool
        """
        return datetime_obj > datetime.now(tz=pytz.utc)

    def convert_to_iso(self, dt_str, action_result, key):
        """
        Converst input date to iso8601 datetime

        :param dt_str: datetime string
        :param action_result: action result object
        :param key: input parameter key
        :return : status and datetime object
        """
        try:
            date_time = parse(dt_str)
            if not date_time.tzinfo:
                date_time = date_time.replace(tzinfo=pytz.utc)
            if self.check_for_future_datetime(date_time):
                return (
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Please provide a valid value for parameter '{key}'",
                    ),
                    None,
                )

        except Exception:
            return (
                action_result.set_status(
                    phantom.APP_ERROR, f"Parameter '{key}' is invalid"
                ),
                None,
            )
        return (phantom.APP_SUCCESS, date_time)

    def check_starttime_greater_than_endtime(self, datetime_start, datetime_end):
        """
        Checks if starttime is greater than endtime or not

        :param datetime_start: start datetime obj
        :param datetime_end: end datetime obj
        :return : bool
        """
        return datetime_start > datetime_end

    def connect_pce(self):
        """
        Connects to the PCE server

        :return: pce obj value
        """
        try:
            pce = illumio.PolicyComputeEngine(
                self._hostname, port=str(self._port), org_id=str(self._org_id)
            )
            pce.set_credentials(self._api_key, self._api_secret)
            test_connection = pce.check_connection()

        except IllumioException as e:
            self.set_status(
                phantom.APP_ERROR, f"Encountered error while conecting to PCE: {e}"
            )
            return None

        return pce if test_connection else None

    def convert_object_to_json(self, obj):
        """
        Converts result object to json

        :param obj: result object
        :return : json
        """

        try:
            json_data = json.loads(json.dumps(obj, cls=illumio.util.IllumioEncoder))
        except IllumioException as e:
            self.set_status(
                phantom.APP_ERROR, f"Encountered error while processing response: {e}"
            )
            return {}
        return json_data

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """
        Checks if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :param allow_zero: whether zero should be considered valid value or not
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Please provide a valid integer value in the {key} parameter",
                    )
                    return None
                parameter = int(parameter)

            except Exception:
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid integer value in the {key} parameter",
                )
                return None

            if parameter < 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid non-negative integer value in the {key} parameter",
                )

                return None
            if not allow_zero and parameter == 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a positive integer value in the {key} parameter",
                )

                return None

        return parameter

    def finalize(self):
        """Perform some final operations or clean up operations."""
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = IllumioConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IllumioConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()

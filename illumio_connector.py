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

from illumio_consts import *
import sys
import requests
import json
import illumio
from datetime import datetime
from dateutil.parser import parse
import pytz

from illumio.exceptions import IllumioException


class IllumioConnector(BaseConnector):
    """Represent a connector module that implements the actions that are provided by the app."""

    def __init__(self):
        """Initialize class variables."""
        # Call the BaseConnectors init first
        super(IllumioConnector, self).__init__()

        self._state = None
        self._api_key = None
        self._api_secret = None
        self._hostname = None
        self._port = None
        self._org_id = None
        self._pce = None

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to PCE")

        if self.connect_pce(action_result):
            self.save_progress("Connectivity Test Passed")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Connectivity Test Failed")
            return action_result.set_status(phantom.APP_ERROR)

    def _handle_get_traffic_analysis(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, end_time = self.parse_and_validate_date(
            param["end_time"], action_result, "end_time"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, start_time = self.parse_and_validate_date(
            param["start_time"], action_result, "start_time"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if self.check_starttime_greater_than_endtime(start_time, end_time):
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'end_time' parameter must be greater than 'start_time' parameter",
            )

        ret_val, port = self._validate_integer(
            action_result, param["port"], "port", max=PORT_MAX_VALUE
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        protocol = param["protocol"].lower()
        if protocol not in PROTOCOL_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, "Please enter a valid value for 'protocol' parameter"
            )

        policy_decisions_string = param["policy_decisions"].lower()

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            policy_decisions_list = self.handle_comma_seperated_string(
                policy_decisions_string
            )

            traffic_query = illumio.TrafficQuery.build(
                start_date=start_time.isoformat(),
                end_date=end_time.isoformat(),
                include_services=[{"port": port, "proto": protocol}],
                policy_decisions=policy_decisions_list,
            )

            traffic_flow_list = self._pce.get_traffic_flows_async(
                query_name="phantom_block_port_traffic_query",
                traffic_query=traffic_query,
            )

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error while running traffic query: {}".format(e),
            )

        traffic_list_length = len(traffic_flow_list)

        self.debug_print(
            "Found {} records for the specified time range".format(traffic_list_length)
        )

        result = {
            "traffic_flows": [
                self.convert_object_to_json(flow, action_result)
                for flow in traffic_flow_list
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

    def _handle_create_virtual_service(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, port = self._validate_integer(
            action_result, param["port"], "port", max=PORT_MAX_VALUE
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        protocol = param["protocol"].lower()
        if protocol not in PROTOCOL_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, ILLUMIO_INVALID_PROTOCOL_MSG
            )

        service_name = param["name"]
        virtual_service = None

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            virtual_service = illumio.VirtualService(
                name=service_name,
                service_ports=[illumio.ServicePort(port=port, proto=protocol)],
            )
            virtual_service = self._pce.virtual_services.create(virtual_service)
            action_result.set_status(
                phantom.APP_SUCCESS, "Successfully created virtual service"
            )

        except IllumioException as e:
            if ILLUMIO_EXISTING_VIRTUAL_SERVICE_MSG in e:
                service_list = self._pce.virtual_services.get(
                    params={"name": service_name}
                )
                for service in service_list:
                    if service_name == service.name:
                        virtual_service = service
                        action_result.set_status(
                            phantom.APP_SUCCESS,
                            "Found existing virtual service with name {}".format(
                                service_name
                            ),
                        )
                        break
            else:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Encountered error creating virtual service: {}".format(e),
                )

        result = self.convert_object_to_json(virtual_service, action_result)
        action_result.add_data(result)
        return action_result.get_status()

    def _handle_provision_objects(self, param):
        hrefs = param["hrefs"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            hrefs_list = self.handle_comma_seperated_string(hrefs)

            provisioned_virtual_service_obj = self._pce.provision_policy_changes(
                change_description="Phantom object provisioning.",
                hrefs=hrefs_list,
            )

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error provisioning object: {}".format(e),
            )

        result = self.convert_object_to_json(
            provisioned_virtual_service_obj, action_result
        )
        action_result.add_data(result)
        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully provisioned object"
        )

    def _handle_get_ip_lists(self, param):
        name = param.get("name")
        description = param.get("description")
        fqdn = param.get("fqdn")
        ip_address = param.get("ip_address")

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            ip_list = self._pce.ip_lists.get(
                params={
                    "name": name,
                    "description": description,
                    "fqdn": fqdn,
                    "ip_address": ip_address,
                }
            )
            output_msg = "Successfully fetched IP List" if ip_list else "No Data Found"
            action_result.set_status(phantom.APP_SUCCESS, output_msg)

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error fetching IP List: {}".format(e),
            )

        result = {
            "ip_lists": [
                self.convert_object_to_json(lists, action_result) for lists in ip_list
            ]
        }
        action_result.add_data(result)
        return action_result.get_status()

    def _handle_create_ruleset(self, param):
        name = param["name"]

        action_result = self.add_action_result(ActionResult(dict(param)))

        rule_set = None

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            rule_set = illumio.RuleSet(name=name, scopes=[illumio.LabelSet(labels=[])])
            rule_set = self._pce.rule_sets.create(rule_set)
            action_result.set_status(
                phantom.APP_SUCCESS, "Successfully created ruleset"
            )
        except IllumioException as e:
            if ILLUMIO_EXISTING_RULE_SET_MSG in e:
                ruleset_list = self._pce.rule_sets.get(params={"name": name})
                for ruleset in ruleset_list:
                    if name == ruleset.name:
                        rule_set = ruleset
                        action_result.set_status(
                            phantom.APP_SUCCESS,
                            "Found existing ruleset with name {}".format(name),
                        )
                        break

            else:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Encountered error creating ruleset: {}".format(e),
                )

        result = self.convert_object_to_json(rule_set, action_result)
        action_result.add_data(result)
        return action_result.get_status()

    def handle_comma_seperated_string(self, comma_str):
        """
        Convert comma seperated string into list.

        :param comma_str: comma seperated string
        :return : list
        """
        str_to_list = [x.strip() for x in comma_str.split(",") if x]
        return str_to_list

    def _handle_create_rule(self, param):
        providers_list = self.handle_comma_seperated_string(param["providers"])
        consumers_list = self.handle_comma_seperated_string(param["consumers"])
        ruleset_href = param["ruleset_href"]
        resolve_consumers_as_list = self.handle_comma_seperated_string(
            param["resolve_consumers_as"]
        )
        resolve_providers_as_list = self.handle_comma_seperated_string(
            param["resolve_providers_as"]
        )

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            rule = illumio.Rule.build(
                providers=providers_list,
                consumers=consumers_list,
                resolve_providers_as=resolve_providers_as_list,
                resolve_consumers_as=resolve_consumers_as_list,
                ingress_services=[],
            )
            rule = self._pce.rules.create(rule, parent=ruleset_href)
        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error creating rule: {}".format(e),
            )

        result = self.convert_object_to_json(rule, action_result)
        action_result.add_data(result)
        return action_result.set_status(
            phantom.APP_SUCCESS, "Successfully created rule"
        )

    def _handle_create_service_binding(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        workload_hrefs_list = self.handle_comma_seperated_string(
            param["workload_hrefs"]
        )
        virtual_service_href = param["virtual_service_href"]

        ret_val = self.connect_pce(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            service_bindings = self._pce.service_bindings.create(
                [
                    {
                        "workload": {"href": workload_href},
                        "virtual_service": {"href": virtual_service_href},
                        "port_overrides": [],
                    }
                    for workload_href in workload_hrefs_list
                ]
            )

            action_result.set_status(
                phantom.APP_SUCCESS, "Successfully bound workloads with virtual service"
            )

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error creating service binding: {}".format(e),
            )

        service_bindings["service_bindings"] = [
            sb.to_json() for sb in service_bindings["service_bindings"]
        ]

        action_result.add_data(service_bindings)
        return action_result.get_status()

    def handle_action(self, param):
        """Get current action identifier and call member function of its own to handle the action."""
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "get_traffic_analysis":
            ret_val = self._handle_get_traffic_analysis(param)
        elif action_id == "create_virtual_service":
            ret_val = self._handle_create_virtual_service(param)
        elif action_id == "provision_objects":
            ret_val = self._handle_provision_objects(param)
        elif action_id == "get_ip_lists":
            ret_val = self._handle_get_ip_lists(param)
        elif action_id == "create_ruleset":
            ret_val = self._handle_create_ruleset(param)
        elif action_id == "create_rule":
            ret_val = self._handle_create_rule(param)
        elif action_id == "create_service_binding":
            ret_val = self._handle_create_service_binding(param)

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

        ret_val, self._port = self._validate_integer(
            self, config["port"], "port", max=PORT_MAX_VALUE
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        ret_val, self._org_id = self._validate_integer(
            self, config["org_id"], "org_id", min=1
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        return phantom.APP_SUCCESS

    def check_for_future_datetime(self, datetime_obj):
        """
        Check the given datetime str is a future date or not.

        :param datetime_obj: datetime object
        :return : bool
        """
        return datetime_obj > datetime.now(tz=pytz.utc)

    def parse_and_validate_date(self, dt_str, action_result, key):
        """
        Convert input date to iso8601 datetime.

        :param dt_str: datetime string
        :param action_result: action result object
        :param key: input parameter key
        :return : status and datetime object
        """
        try:
            date_time = parse(dt_str)
            if not date_time.tzinfo:
                date_time = date_time.replace(tzinfo=pytz.utc)
            date_time = date_time.astimezone(pytz.utc)
            if self.check_for_future_datetime(date_time):
                return (
                    action_result.set_status(
                        phantom.APP_ERROR,
                        "The provided time is a future datetime. Please provide a valid value for parameter '{}'".format(
                            key
                        ),
                    ),
                    None,
                )

        except Exception:
            return (
                action_result.set_status(
                    phantom.APP_ERROR, "Parameter '{}' is invalid".format(key)
                ),
                None,
            )
        return (phantom.APP_SUCCESS, date_time)

    def check_starttime_greater_than_endtime(self, datetime_start, datetime_end):
        """
        Check if the starttime is greater than endtime or not.

        :param datetime_start: start datetime obj
        :param datetime_end: end datetime obj
        :return : bool
        """
        return datetime_start > datetime_end

    def connect_pce(self, action_result):
        """
        Connect to the PCE server.

        :return: pce obj value
        """
        try:
            self._pce = illumio.PolicyComputeEngine(
                self._hostname, port=str(self._port), org_id=str(self._org_id)
            )
            self._pce.set_credentials(self._api_key, self._api_secret)
            test_connection = self._pce.check_connection()

        except IllumioException as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error while conecting to PCE: {}".format(e),
            )

        return (
            phantom.APP_SUCCESS
            if test_connection
            else action_result.set_status(phantom.APP_ERROR, "Failed to connect to PCE")
        )

    def convert_object_to_json(self, obj, action_result):
        """
        Convert result object to json.

        :param obj: result object
        :return : json
        """
        try:
            json_data = obj.to_json()
        except Exception as e:
            action_result.set_status(
                phantom.APP_ERROR,
                "Encountered error while processing response: {}".format(e),
            )
            return {}
        return json_data

    def _validate_integer(self, action_result, parameter, key, min=0, max=sys.maxsize):
        """
        Check if the provided input parameter value is a integer and returns the integer value of the parameter itself.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :param min: minimum allowed integer value
        :param max: maximum allowed integer value
        :return: integer value of the parameter or None in case of failure
        """
        error_message = (
            "Please provide a valid integer value for the '{}' parameter".format(key)
        )
        if parameter is not None:
            try:
                parameter = int(parameter)
                if min <= parameter <= max:
                    return phantom.APP_SUCCESS, parameter
                else:
                    error_message = "Invalid integer value for parameter {}: please enter value between {} and {}".format(
                        key, min, max
                    )
            except Exception:
                pass  # fall through to the default failure response
        return action_result.set_status(phantom.APP_ERROR, error_message), None

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

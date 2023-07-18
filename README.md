[comment]: # "Auto-generated SOAR connector documentation"
# Illumio

Publisher: Illumio  
Connector Version: 1.0.0  
Product Vendor: Illumio  
Product Name: Illumio  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

This app integrates with the Illumio Policy Compute Engine to implement actions for automating workload containment

[comment]: # " File: README.md"
[comment]: # ""
[comment]: # "    Copyright (c) Illumio, 2023"
[comment]: # ""
[comment]: # "    This unpublished material is proprietary to Illumio."
[comment]: # "    All rights reserved. The methods and"
[comment]: # "    techniques described herein are considered trade secrets"
[comment]: # "    and/or confidential. Reproduction or distribution, in whole"
[comment]: # "    or in part, is forbidden except by express written permission"
[comment]: # "    of Illumio."
[comment]: # ""
[comment]: # "    Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "    you may not use this file except in compliance with the License."
[comment]: # "    You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "        http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "    Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "    the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "    either express or implied. See the License for the specific language governing permissions"
[comment]: # "    and limitations under the License."
[comment]: # ""
The Illumio connector for Splunk SOAR provides selective port-blocking through integration with the
Illumio Policy Compute Engine (PCE).

This Readme explains the actions this app provides, and the asset configuration or action parameters
associated with it. For further details, refer to [the Illumio Core API
Reference](https://docs.illumio.com/core/22.5/API-Reference/index.html#Illumio-Core) on the Illumio
Documentation Portal.

## SDK Version

The app uses Illumio SDK version 1.1.3 for communicating with the Illumio PCE.

## Configuring Assets

Follow these steps to create an Illumio app asset for your Splunk SOAR Platform:

-   Log into the Illumio Policy Compute Engine (PCE).

      

    1.  Click the user name drop-down in the top-right corner of the PCE interface, and select **My
        API Keys** from the menu.

    2.  The 'API Keys' page opens. Click **Add** .

    3.  The 'Create API Key' page opens. Enter a unique Name for your API key and an optional
        Description.

    4.  Note the **Org ID** value in the dialog, as you will need it later when configuring the
        asset.

    5.  Click **Create** to create the new API key.

    6.  After successfully creating a new API key, the 'API Key Created' dialog is shown, containing
        the **Key ID** and **Secret** .

    7.  Note the **Authentication Username** and **Secret** values from the dialog box, and click
        **Download Credentials** to store a backup in a secure location, as the **Secret** value
        will not be visible again once the dialog is closed. Once saved, click **Close** .

        This secret value is the **API Secret** , and the **Authentication Username** value is the
        **API Key** that will be used in the asset.

-   Log in to your Splunk SOAR platform.

      

    -   Navigate to the **Home** dropdown and select **Apps** .
    -   Search the Illumio App from the search box.
    -   Click on the **CONFIGURE NEW ASSET** button.
    -   Navigate to the **Asset Info** tab and enter the Asset name and Asset description.
    -   Navigate to the **Asset Settings** tab.
    -   Enter the **API Key, API Secret, and Org ID** values from the previous step to their
        respective configuration parameters.
    -   Enter the PCE FQDN and HTTPS port as the **Host** and **Port** parameters respectively.
    -   Save the asset.
    -   Now, test the connectivity of the Splunk SOAR server to the Illumio instance by clicking on
        the **TEST CONNECTIVITY** button.

## Asset Configuration Parameters

-   **API Key:** The API key name for the key created in the previous steps.
-   **API Secret:** The API secret for asset authentication.
-   **Hostname:** The PCE fully-qualified domain name.
-   **Port:** The HTTPS port number on which the PCE is hosted.
-   **Org ID:** ID number of your organization in the PCE.

## Illumio Action Parameters

-   ### Test Connectivity (Action Workflow Details)

    -   This action tests the connectivity of the Phantom server to the Illumio instance by using
        the provided asset configuration parameters.
    -   The action validates the provided asset configuration parameters. Based on the response from
        the SDK method, the appropriate success and failure message is displayed when the action is
        executed.

-   ### Get Traffic Analysis

    Runs an Explorer query to get a traffic analysis report based on the provided inputs. The query
    checks all sources and destinations for traffic on a given port.

    The following parameters for this action are supported:

    -   **Start Time**

          

        -   This parameter accepts the start datetime for the traffic analysis. An error message is
            shown if the datetime is invalid. Start Time supports human readable or ISO datetime
            values.

    -   **End Time**

          

        -   This parameter accepts the end datetime for the traffic analysis. An error message is
            shown if the datetime is invalid. End Time supports human readable or ISO datetime
            values.

    -   **Port**

          

        -   This parameter accepts the port value for traffic. It expects a numeric value as an
            input. An error message is shown if the port value is invalid.

    -   **Protocol**

          

        -   This parameter allows the user to select TCP or UDP as protocol for traffic. The default
            value is TCP.

    -   **Policy Decisions**

          

        -   This parameter filters the traffic based on policy decisions. An error message is shown
            if the policy decision is invalid. Valid values are **allowed** ,
            **potentially_blocked** , **blocked** , and **unknown**

    -   **Examples:**
        -   Retrieve traffic from between 01 July, 2022 to 10 July, 2022 on 22 TCP and having policy
            decision potentially_blocked.
            -   Start Time = "2022-07-01T17:45:08"
            -   End Time = "2022-07-10T17:45:08"
            -   Port = 22
            -   Protocol = "TCP"
            -   Policy Decisions = "potentially_blocked"

-   ### Create Virtual Service

    Creates a virtual service.

    The following parameters for this action are supported:

    -   **Port**

          

        -   This parameter accepts the port value for the virtual service. It expects a numeric
            value as an input. An error message is shown if the port value is invalid.

    -   **Protocol**

          

        -   This parameter allows the user to select TCP or UDP from a drop-down menu as the
            protocol for the virtual service.

    -   **Name**

          

        -   This parameter specifies the name for the new virtual service.

    -   **Examples:**
        -   Create a new virtual service with name "test-vs" on port 22 and protocol "TCP".
            -   Port = 22
            -   Protocol = "TCP"
            -   Name = "test-vs"

-   ### Create Service Binding

    Binds one or more workloads to a virtual service. The virtual service must be provisioned into
    the active state to bind a workload to it.

    The following parameters for this action are supported:

    -   **Workload hrefs**

          

        -   This parameter accepts the href of one or more workloads to be bound to a virtual
            service. It accepts multiple comma-seperated workload hrefs. An error message is shown
            if any href value is invalid.

    -   **Virtual Service href**

          

        -   This parameter accepts the href of a virtual service for binding. An error message is
            shown if the href value is invalid.

    -   **Examples:**
        -   Bind workloads
            "/orgs/1/workloads/abd71956-0953-4a3f-b7f7-9aecaebbc358,/orgs/1/workloads/6ee0434b-46a8-48e3-b813-bdde9ccb1c41"
            to virtual service
            "/orgs/1/sec_policy/active/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4"

              

            -   Workload hrefs =
                "/orgs/1/workloads/abd71956-0953-4a3f-b7f7-9aecaebbc358,/orgs/1/workloads/6ee0434b-46a8-48e3-b813-bdde9ccb1c41"
            -   Virtual Service href =
                "/orgs/1/sec_policy/active/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4"

-   ### Get IP Lists

    Gets a list of IP list objects.

    The following parameters for this action are supported:

    -   **name**

          

        -   This parameter accepts the name of an IP list.

    -   **description**

          

        -   This parameter accepts a description of an IP list.

    -   **fqdn**

          

        -   This parameter accepts the FQDN value of an IP list.

    -   **ip_address**

          

        -   This parameter accepts the IP address value attached to an IP list.

    -   **Examples:**
        -   Retrive IP lists with IP address as 1.1.1.1, name as "iplist1", description as "test
            iplist" and FQDN as "www.illumio.com:"

              

            -   name="iplist1"
            -   description = "test iplist"
            -   fqdn = "www.illumio.com"
            -   ip_address = "1.1.1.1"

-   ### Create Ruleset

    Creates a ruleset security policy object.

    The following parameters for this action are supported:

    -   **name**

          

        -   This parameter accepts the name for the new ruleset.

    -   **Examples:**
        -   Create a new ruleset named "test-rs:"

              

            -   name="test-rs"

-   ### Create Rule

    Creates a policy rule within a given ruleset.

    The following parameters for this action are supported:

    -   **consumer**

          

        -   This parameter accepts the href of consumers when creating a new rule.

    -   **provider**

          

        -   This parameter accepts the href of providers when creating a new rule.

    -   **ruleset_href**

          

        -   This parameter accepts the href of parent ruleset when creating a new rule.

    -   **resolve_consumers_as**

          

        -   This parameter accepts a value for the consumer to resolve rule.

    -   **resolve_providers_as**

          

        -   This parameter accepts a value for the provider to resolve rule.

    -   **Examples:**
        -   Create new rule with provider as
            "/orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4",
            consumer as "/orgs/1/sec_policy/active/ip_lists/958", ruleset as
            "/orgs/1/sec_policy/draft/rule_sets/1611", resolve_consumers_as "workloads",
            resolve_providers_as "virtual_services"

              

            -   consumer="/orgs/1/sec_policy/active/ip_lists/958"
            -   provider="/orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4"
            -   ruleset_href="/orgs/1/sec_policy/draft/rule_sets/1611"
            -   resolve_providers_as="virtual_services"
            -   resolve_consumers_as="workloads"

-   ### Create Enforcement Boundary

    Creates an enforcement boundary with an ingress service using the given port and protocol.

    The following parameters for this action are supported:

    -   **consumer**

          

        -   This parameter accepts the href of consumers for creating new enforcement boundary.

    -   **provider**

          

        -   This parameter accepts the href of providers for creating new enforcement boundary.

    -   **name**

          

        -   This parameter accepts a name for creating new enforcement boundary.

    -   **port**

          

        -   This parameter accepts the port value for a virtual service. It expects a numeric value
            as an input. An error message is shown if the port value is invalid.

    -   **protocol**

          

        -   This parameter allows the user to select TCP or UDP from dropdown as protocol for
            virtual service

    -   **Examples:**
        -   Create new rule with provider as all workloads, consumer as
            "/orgs/1/sec_policy/active/ip_lists/958", name as "test-eb"

              

            -   consumer="/orgs/1/sec_policy/active/ip_lists/958"
            -   provider="ams" (NOTE: where "ams" represents all workloads)
            -   name="test-eb"
            -   port=22
            -   protocol="TCP"

-   ### Update Enforcement Mode

    Updates the enforcement mode for one or more workloads.

    The following parameters for this action are supported:

    -   **workload_hrefs**

          

        -   This parameter accepts a list of workload HREFs for updating their enforcement mode.

    -   **enforcement_mode**

          

        -   The enforcement mode to apply to the workloads specified by **workload_hrefs** . Valid
            values are **idle** , **visibility_only** , **selective** , and **full** .

    -   **Examples:**
        -   Update enforcement mode of workload
            "/orgs/1/workloads/bd004cd5-f37c-4823-9ec9-cb1773dd11fc" to "selective"

              

            -   workload_hrefs="/orgs/1/workloads/bd004cd5-f37c-4823-9ec9-cb1773dd11fc"
            -   enforcement_mode="selective"

-   ### Provision Objects

    Provision draft policy changes for the given security policy objects.

    The following parameters for this action are supported:

    -   **hrefs**

          

        -   This parameter accepts a list of HREFs for provisioning.

    -   **Examples:**
        -   Provision virtual service
            "/orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4"

              

            -   hrefs="/orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4"

-   ### Get Workloads

    Gets multiple workloads based on the given search criteria.

    The following parameters for this action are supported:

    -   **max_results**

          

        -   This parameter allows the user to limit the number of workloads to be fetched.

    -   **enforcement_mode**

          

        -   This parameter allows the user to select the enforcement mode for the selected
            workloads.

    -   **connectivity**

          

        -   This parameter allows the user to select connectivity for the selected workloads.

    -   **name**

          

        -   This parameter accepts a name value for the selected workloads.

    -   **labels**

          

        -   This parameter accepts a list of labels for the selected workloads.

    -   **ip_address**

          

        -   This parameter accepts an IP address value for the selected workloads.

    -   **description**

          

        -   This parameter accepts a description for the selected workloads.

    -   **hostname**

          

        -   This parameter accepts a hostname value for the selected workloads.

    -   **os_id**

          

        -   This parameter accepts the os_id value for the selected workloads.

    -   **Examples:**
        -   Fetch a list of 600 workloads with name as "test", enforcement_mode "visibility_only",
            connectivity "online", labels "/orgs/1/labels/27380", ip_address "1.1.1.1", description
            "test workload", hostname "Perf_test 16608" and os_id "ubuntu-x86_64-xenial"

              

            -   max_results=600
            -   enforcement_mode="visibility_only"
            -   connectivity="online
            -   name="test"
            -   labels="/orgs/1/labels/27380"
            -   ip_address="1.1.1.1"
            -   description="test workload"
            -   hostname="centos7"
            -   os_id="ubuntu-x86_64-xenial"


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Illumio asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**hostname** |  required  | string | Hostname
**port** |  required  | numeric | Port
**api_key** |  required  | password | API Key
**api_secret** |  required  | password | API Secret
**org_id** |  required  | numeric | Org ID

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get traffic analysis](#action-get-traffic-analysis) - List of traffic on specified port  
[create virtual service](#action-create-virtual-service) - Creates a new virtual service  
[provision objects](#action-provision-objects) - Provisions the specified objects  
[get ip lists](#action-get-ip-lists) - Get IP list of specified name  
[create ruleset](#action-create-ruleset) - Create ruleset  
[create rule](#action-create-rule) - Create rule  
[create enforcement boundary](#action-create-enforcement-boundary) - Creates enforcement boundary  
[get workloads](#action-get-workloads) - Gets list of workloads for a given enforcement mode  
[create service binding](#action-create-service-binding) - Binds workload with virtual service  
[update enforcement mode](#action-update-enforcement-mode) - Update enforcement mode of workloads  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get traffic analysis'
List of traffic on specified port

Type: **investigate**  
Read only: **True**

Allowed values for 'policy_decisions' parameter are: allowed, unknown, potentially_blocked, and blocked. Valid date format allowed: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss. Supported timezone offset format for parameters 'start_time' and 'end_time' are Z(UTC), HH:MM, HHMM and HH.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** |  required  | Start time for traffic analysis (Valid date format allowed: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss) | string | 
**end_time** |  required  | End time for traffic analysis (Valid date format allowed: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss) | string | 
**port** |  required  | Port number (Maximum port value is 65535) | numeric |  `port` 
**protocol** |  required  | Protocol | string | 
**policy_decisions** |  required  | Policy decisions (Comma-seperated values are allowed) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.end_time | string |  |   2022-08-02T14:32:45.135761 
action_result.parameter.policy_decisions | string |  |   unknown 
action_result.parameter.port | numeric |  `port`  |   22 
action_result.parameter.protocol | string |  |   tcp 
action_result.parameter.start_time | string |  |   2022-08-02T14:32:45.135761 
action_result.data.\*.traffic_flows.\*.dst.ip | string |  |   13.234.176.102 
action_result.data.\*.traffic_flows.\*.dst.virtual_service.href | string |  |   /orgs/1/sec_policy/draft/virtual_services/16ab3e56-7cb8-438e-a580-89d55632dae4 
action_result.data.\*.traffic_flows.\*.dst.virtual_service.name | string |  |   Virtual-service-22 
action_result.data.\*.traffic_flows.\*.dst.workload.hostname | string |  |   localhost.localdomain 
action_result.data.\*.traffic_flows.\*.dst.workload.href | string |  `illumio workload href`  |   /orgs/1/workloads/5913e8a8-2f74-4db1-b5aa-280f75dc66b3 
action_result.data.\*.traffic_flows.\*.dst.workload.labels.\*.href | string |  |   /orgs/1/labels/1240 
action_result.data.\*.traffic_flows.\*.dst.workload.name | string |  |   workload-localhost.localdomain 
action_result.data.\*.traffic_flows.\*.dst.workload.os_type | string |  |   linux 
action_result.data.\*.traffic_flows.\*.dst_bi | numeric |  |   0 
action_result.data.\*.traffic_flows.\*.dst_bo | numeric |  |   0 
action_result.data.\*.traffic_flows.\*.flow_direction | string |  |   outbound 
action_result.data.\*.traffic_flows.\*.num_connections | numeric |  |   1 
action_result.data.\*.traffic_flows.\*.policy_decision | string |  |   potentially_blocked 
action_result.data.\*.traffic_flows.\*.service.port | numeric |  |   22 
action_result.data.\*.traffic_flows.\*.service.process_name | string |  |   sshd 
action_result.data.\*.traffic_flows.\*.service.proto | numeric |  |   6 
action_result.data.\*.traffic_flows.\*.service.user_name | string |  |   devuser 
action_result.data.\*.traffic_flows.\*.src.ip | string |  |   10.50.4.153 
action_result.data.\*.traffic_flows.\*.src.ip_lists.\*.href | string |  |   /orgs/1/sec_policy/draft/ip_lists/966 
action_result.data.\*.traffic_flows.\*.src.ip_lists.\*.name | string |  |   test-iplist 
action_result.data.\*.traffic_flows.\*.src.workload.hostname | string |  |   localhost.localdomain 
action_result.data.\*.traffic_flows.\*.src.workload.href | string |  |   /orgs/1/workloads/5913e8a8-2f74-4db1-b5aa-280f75dc66b3 
action_result.data.\*.traffic_flows.\*.src.workload.name | string |  |   workload-localhost.localdomain 
action_result.data.\*.traffic_flows.\*.src.workload.os_type | string |  |   linux 
action_result.data.\*.traffic_flows.\*.state | string |  |   timed out 
action_result.data.\*.traffic_flows.\*.timestamp_range.first_detected | string |  |   2022-07-28T09:07:55Z 
action_result.data.\*.traffic_flows.\*.timestamp_range.last_detected | string |  |   2022-07-28T09:07:55Z 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully fetched traffic flow list 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create virtual service'
Creates a new virtual service

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**port** |  required  | Port | numeric |  `port` 
**protocol** |  required  | Protocol | string | 
**name** |  required  | Virtual service name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.name | string |  |   test_name 
action_result.parameter.port | numeric |  `port`  |   22 
action_result.parameter.protocol | string |  |   tcp 
action_result.data.\*.apply_to | string |  |   host_only 
action_result.data.\*.created_at | string |  |   2022-07-30T11:36:04.014Z 
action_result.data.\*.created_by.href | string |  |   /users/65 
action_result.data.\*.href | string |  `illumio virtual service href`  |   /orgs/1/sec_policy/draft/virtual_services/a62bb999-73ab-42d7-87ab-d493ccc131b6 
action_result.data.\*.name | string |  |   test_vs 
action_result.data.\*.service_ports.\*.port | numeric |  `port`  |   22 
action_result.data.\*.service_ports.\*.proto | numeric |  |   6 
action_result.data.\*.update_type | string |  |   create 
action_result.data.\*.updated_at | string |  |   2022-07-30T11:36:04.017Z 
action_result.data.\*.updated_by.href | string |  |   /users/65 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully created virtual service 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'provision objects'
Provisions the specified objects

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hrefs** |  required  | Object HREFs (Comma-seperated values) | string |  `illumio virtual service href`  `illumio rule href`  `illumio ruleset href`  `illumio enforcement boundary href` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.hrefs | string |  `illumio virtual service href`  `illumio rule href`  `illumio ruleset href`  `illumio enforcement boundary href`  |   /orgs/1/sec_policy/draft/virtual_services/a62bb999-73ab-42d7-87ab-d493ccc131b6 
action_result.data.\*.commit_message | string |  |   Object provisioning 
action_result.data.\*.created_at | string |  |   2022-07-30T12:16:27.257Z 
action_result.data.\*.created_by.href | string |  |   /users/65 
action_result.data.\*.href | string |  |   /orgs/1/sec_policy/1221 
action_result.data.\*.object_counts.enforcement_boundaries | numeric |  |   12 
action_result.data.\*.object_counts.firewall_settings | numeric |  |   1 
action_result.data.\*.object_counts.ip_lists | numeric |  |   20 
action_result.data.\*.object_counts.label_groups | numeric |  |   17 
action_result.data.\*.object_counts.rule_sets | numeric |  |   35 
action_result.data.\*.object_counts.secure_connect_gateways | numeric |  |   0 
action_result.data.\*.object_counts.services | numeric |  |   14 
action_result.data.\*.object_counts.virtual_servers | numeric |  |   0 
action_result.data.\*.object_counts.virtual_services | numeric |  |   50 
action_result.data.\*.provisioned_href | string |  `illumio virtual service href`  `illumio rule href`  `illumio ruleset href`  `illumio enforcement boundary href`  |   /orgs/1/sec_policy/draft/virtual_services/a62bb999-73ab-42d7-87ab-d493ccc131b6 
action_result.data.\*.version | numeric |  |   1221 
action_result.data.\*.workloads_affected | numeric |  |   0 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully provisioned object 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get ip lists'
Get IP list of specified name

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  optional  | Name of IP list | string | 
**description** |  optional  | Description of IP list | string | 
**fqdn** |  optional  | FQDN of IP list | string | 
**ip_address** |  optional  | IP Address linked with IP List | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |   Acc. test description 
action_result.parameter.fqdn | string |  |   app.example.com 
action_result.parameter.ip_address | string |  `ip`  `ipv6`  |   10.6.4.226 
action_result.parameter.name | string |  |   test_ip_list 
action_result.data.\*.ip_lists.\*.created_at | string |  |   2019-04-05T19:58:39.545Z 
action_result.data.\*.ip_lists.\*.created_by.href | string |  |   /users/0 
action_result.data.\*.ip_lists.\*.description | string |  |   Acc. test description 
action_result.data.\*.ip_lists.\*.fqdns.\*.description | string |  |   Acc. test fqdn description 
action_result.data.\*.ip_lists.\*.fqdns.\*.fqdn | string |  |   app.example.com 
action_result.data.\*.ip_lists.\*.href | string |  `illumio ip list href`  |   /orgs/1/sec_policy/draft/ip_lists/1 
action_result.data.\*.ip_lists.\*.ip_ranges.\*.description | string |  |   test ip_ranges description 
action_result.data.\*.ip_lists.\*.ip_ranges.\*.exclusion | boolean |  |   False  True 
action_result.data.\*.ip_lists.\*.ip_ranges.\*.from_ip | string |  |   0.0.0.0/0 
action_result.data.\*.ip_lists.\*.ip_ranges.\*.to_ip | string |  |   10.6.4.226 
action_result.data.\*.ip_lists.\*.name | string |  |   Any (0.0.0.0/0 and ::/0) 
action_result.data.\*.ip_lists.\*.updated_at | string |  |   2019-04-05T19:58:39.552Z 
action_result.data.\*.ip_lists.\*.updated_by.href | string |  |   /users/0 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully fetched IP List 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create ruleset'
Create ruleset

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of ruleset | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.name | string |  |   test_rs 
action_result.data.\*.created_at | string |  |   2022-08-08T12:46:00.394Z 
action_result.data.\*.created_by.href | string |  |   /users/65 
action_result.data.\*.enabled | boolean |  |   True  False 
action_result.data.\*.href | string |  `illumio ruleset href`  |   /orgs/1/sec_policy/draft/rule_sets/1611 
action_result.data.\*.name | string |  |   test_rs 
action_result.data.\*.rules.\*.consumers.\*.ip_list.href | string |  |   /orgs/1/sec_policy/draft/ip_lists/958 
action_result.data.\*.rules.\*.created_at | string |  |   2022-08-08T12:53:05.428Z 
action_result.data.\*.rules.\*.created_by.href | string |  |   /users/65 
action_result.data.\*.rules.\*.enabled | boolean |  |   True  False 
action_result.data.\*.rules.\*.href | string |  |   /orgs/1/sec_policy/draft/rule_sets/1611/sec_rules/1914 
action_result.data.\*.rules.\*.machine_auth | boolean |  |   False  True 
action_result.data.\*.rules.\*.network_type | string |  |   brn 
action_result.data.\*.rules.\*.providers.\*.virtual_service.href | string |  |   /orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4 
action_result.data.\*.rules.\*.sec_connect | boolean |  |   False  True 
action_result.data.\*.rules.\*.stateless | boolean |  |   False  True 
action_result.data.\*.rules.\*.unscoped_consumers | boolean |  |   False  True 
action_result.data.\*.rules.\*.update_type | string |  |   create 
action_result.data.\*.rules.\*.updated_at | string |  |   2022-08-08T12:53:05.439Z 
action_result.data.\*.rules.\*.updated_by.href | string |  |   /users/65 
action_result.data.\*.update_type | string |  |   create 
action_result.data.\*.updated_at | string |  |   2022-08-08T12:46:00.394Z 
action_result.data.\*.updated_by.href | string |  |   /users/65 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully created ruleset 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create rule'
Create rule

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**providers** |  required  | List of HREFS (Comma-seperated values are allowed) | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href` 
**consumers** |  required  | List of HREFS (Comma-seperated values are allowed) | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href` 
**ruleset_href** |  required  | Ruleset HREF | string |  `illumio ruleset href` 
**resolve_consumers_as** |  required  | Consumers (Comma-seperated values are allowed) | string | 
**resolve_providers_as** |  required  | Providers (Comma-seperated values are allowed) | string | 
**ingress_services** |  optional  | Ingress services (Comma-seperated values are allowed) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.consumers | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href`  |   /orgs/1/sec_policy/draft/rule_sets/1611/sec_rules/1914 
action_result.parameter.ingress_services | string |  |   /orgs/1/sec_policy/draft/services/1755 
action_result.parameter.providers | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href`  |   /orgs/1/sec_policy/draft/rule_sets/1611/sec_rules/1914 
action_result.parameter.resolve_consumers_as | string |  |   workloads 
action_result.parameter.resolve_providers_as | string |  |   workloads 
action_result.parameter.ruleset_href | string |  `illumio ruleset href`  |   /orgs/1/sec_policy/draft/rule_sets/1611/sec_rules/1914 
action_result.data.\*.consumers.\*.ip_list.href | string |  `illumio ip list href`  |   /orgs/1/sec_policy/draft/ip_lists/958 
action_result.data.\*.created_at | string |  |   2022-08-08T12:53:05.428Z 
action_result.data.\*.created_by.href | string |  |   /users/65 
action_result.data.\*.enabled | boolean |  |   True  False 
action_result.data.\*.href | string |  `illumio ruleset href`  |   /orgs/1/sec_policy/draft/rule_sets/11110/sec_rules/18665 
action_result.data.\*.ingress_services | string |  |  
action_result.data.\*.machine_auth | boolean |  |   False  True 
action_result.data.\*.network_type | string |  |   brn 
action_result.data.\*.providers.\*.virtual_service.href | string |  `illumio virtual service href`  |   /orgs/1/sec_policy/draft/virtual_services/ce3387fd-703a-4068-a3d2-6e71d63068f4 
action_result.data.\*.sec_connect | boolean |  |   False  True 
action_result.data.\*.stateless | boolean |  |   False  True 
action_result.data.\*.unscoped_consumers | boolean |  |   False  True 
action_result.data.\*.update_type | string |  |   create 
action_result.data.\*.updated_at | string |  |   2022-08-08T12:53:05.439Z 
action_result.data.\*.updated_by.href | string |  |   /users/65 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully created rule 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create enforcement boundary'
Creates enforcement boundary

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**providers** |  required  | List of HREFs (Comma-seperated values are allowed) | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href` 
**consumers** |  required  | List of HREFs (Comma-seperated values are allowed) | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href` 
**name** |  required  | Name of enforcement boundary | string | 
**port** |  required  | Port number (Maximum port value is 65535) | numeric |  `port` 
**protocol** |  required  | Protocol | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.consumers | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href`  |   /orgs/1/sec_policy/draft/ip_lists/958 
action_result.parameter.name | string |  |   test_y_eb 
action_result.parameter.port | numeric |  `port`  |   22 
action_result.parameter.protocol | numeric |  |   6 
action_result.parameter.providers | string |  `illumio virtual service href`  `illumio ip list href`  `illumio workload href`  |   /orgs/1/sec_policy/draft/ip_lists/958 
action_result.data.\*.consumers.\*.ip_list.href | string |  `illumio ip list href`  |   /orgs/1/sec_policy/draft/ip_lists/958 
action_result.data.\*.href | string |  `illumio enforcement boundary href`  |   /orgs/1/sec_policy/active/enforcement_boundaries/1019 
action_result.data.\*.ingress_services.\*.port | numeric |  |   22 
action_result.data.\*.ingress_services.\*.proto | numeric |  |   6 
action_result.data.\*.name | string |  |   test_y_eb 
action_result.data.\*.providers.\*.actors | string |  |   ams 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully created enforcement boundary 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get workloads'
Gets list of workloads for a given enforcement mode

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**max_results** |  optional  | Maximum workloads to fetch (Default value is 500) | numeric | 
**enforcement_mode** |  optional  | Enforcement mode | string | 
**online** |  optional  | Online | string | 
**managed** |  optional  | Managed | string | 
**name** |  optional  | Workload Name | string | 
**labels** |  optional  | Label HREFs (Comma-seperated values are allowed) | string | 
**public_ip_address** |  optional  | Public IP Address | string |  `ip`  `ipv6` 
**description** |  optional  | Workload Description | string | 
**hostname** |  optional  | Hostname | string | 
**os_id** |  optional  | OS ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.description | string |  |   Updated by System Administrator [dev112443.now.com] at February 23, 2022 2:11:30 AM PST 
action_result.parameter.enforcement_mode | string |  |   visibility_only 
action_result.parameter.max_results | numeric |  |   600 
action_result.parameter.hostname | string |  |   ip-172-31-0-22 
action_result.parameter.labels | string |  |   API 
action_result.parameter.managed | string |  |   True  False 
action_result.parameter.name | string |  |   test-vs 
action_result.parameter.online | string |  |   True  False 
action_result.parameter.os_id | string |  |   ubuntu-x86_64-xenial 
action_result.parameter.public_ip_address | string |  `ip`  `ipv6`  |   1.2.3.4 
action_result.data.\*.workloads.\*.agent.config.log_traffic | boolean |  |   False  True 
action_result.data.\*.workloads.\*.agent.config.mode | string |  |   illuminated 
action_result.data.\*.workloads.\*.agent.config.security_policy_update_mode | string |  |   adaptive 
action_result.data.\*.workloads.\*.agent.config.visibility_level | string |  |   flow_summary 
action_result.data.\*.workloads.\*.agent.href | string |  |   /orgs/1/agents/62194 
action_result.data.\*.workloads.\*.agent.secure_connect.matching_issuer_name | string |  |  
action_result.data.\*.workloads.\*.agent.status.agent_version | string |  |   20.2.0 
action_result.data.\*.workloads.\*.agent.status.firewall_rule_count | numeric |  |   0 
action_result.data.\*.workloads.\*.agent.status.fw_config_current | boolean |  |   False  True 
action_result.data.\*.workloads.\*.agent.status.instance_id | string |  |   i-0c1813821cdca1a8b 
action_result.data.\*.workloads.\*.agent.status.last_heartbeat_on | string |  |   2020-10-22T01:52:38.527248Z 
action_result.data.\*.workloads.\*.agent.status.managed_since | string |  |   2020-10-22T01:52:37.714209Z 
action_result.data.\*.workloads.\*.agent.status.security_policy_applied_at | string |  |   2022-08-07T06:40:24.709347Z 
action_result.data.\*.workloads.\*.agent.status.security_policy_received_at | string |  |   2022-08-07T06:40:24.709347Z 
action_result.data.\*.workloads.\*.agent.status.security_policy_refresh_at | string |  |   2022-08-07T06:40:24.709347Z 
action_result.data.\*.workloads.\*.agent.status.security_policy_sync_state | string |  |   syncing 
action_result.data.\*.workloads.\*.agent.status.status | string |  |   active 
action_result.data.\*.workloads.\*.agent.status.uid | string |  |   us-west-2c+i-0c1813821cdca1a8b 
action_result.data.\*.workloads.\*.agent.status.uptime_seconds | numeric |  |   0 
action_result.data.\*.workloads.\*.agent.type | string |  |   Host 
action_result.data.\*.workloads.\*.agent.unpair_allowed | boolean |  |   True  False 
action_result.data.\*.workloads.\*.blocked_connection_action | string |  |   drop 
action_result.data.\*.workloads.\*.containers_inherit_host_policy | boolean |  |   False  True 
action_result.data.\*.workloads.\*.created_at | string |  |   2020-10-22T01:52:37.679879Z 
action_result.data.\*.workloads.\*.created_by.href | string |  |   /orgs/1/agents/62194 
action_result.data.\*.workloads.\*.data_center | string |  |   us-west-2.amazonaws.com 
action_result.data.\*.workloads.\*.data_center_zone | string |  |   us-west-2c 
action_result.data.\*.workloads.\*.deleted | boolean |  |   False  True 
action_result.data.\*.workloads.\*.description | string |  |   Updated by System Administrator [ven02375.service-now.com] at June 16, 2022 8:47:22 AM PDT 
action_result.data.\*.workloads.\*.enforcement_mode | string |  |   visibility_only 
action_result.data.\*.workloads.\*.firewall_coexistence.illumio_primary | boolean |  |   True  False 
action_result.data.\*.workloads.\*.hostname | string |  |   perf-workload-62194 
action_result.data.\*.workloads.\*.href | string |  `illumio workload href`  |   /orgs/1/workloads/bb558b7b-bd43-41f1-bdd9-e576728ca81b 
action_result.data.\*.workloads.\*.interfaces.\*.address | string |  |   fd00::200:a:0:f2f2 
action_result.data.\*.workloads.\*.interfaces.\*.cidr_block | numeric |  |   64 
action_result.data.\*.workloads.\*.interfaces.\*.default_gateway_address | string |  |   10.0.0.1 
action_result.data.\*.workloads.\*.interfaces.\*.link_state | string |  |   unknown 
action_result.data.\*.workloads.\*.interfaces.\*.loopback | boolean |  |   False  True 
action_result.data.\*.workloads.\*.interfaces.\*.name | string |  |   eth0 
action_result.data.\*.workloads.\*.interfaces.\*.network.href | string |  |   /orgs/1/networks/04ac9819-d438-42b6-b892-2968e32ca255 
action_result.data.\*.workloads.\*.interfaces.\*.network_detection_mode | string |  |   single_private_brn 
action_result.data.\*.workloads.\*.labels.\*.href | string |  |   /orgs/1/labels/1 
action_result.data.\*.workloads.\*.name | string |  |   v-11.186 
action_result.data.\*.workloads.\*.online | boolean |  |   False  True 
action_result.data.\*.workloads.\*.os_detail | string |  |   4.4.0-97-generic #120-Ubuntu SMP Tue Sep 19 17:28:18 UTC 2017 (Ubuntu 16.04.1 LTS) 
action_result.data.\*.workloads.\*.os_id | string |  |   ubuntu-x86_64-xenial 
action_result.data.\*.workloads.\*.public_ip | string |  |   66.151.147.220 
action_result.data.\*.workloads.\*.service_provider | string |  |   amazonaws.com 
action_result.data.\*.workloads.\*.updated_at | string |  |   2022-02-07T16:02:00.917702Z 
action_result.data.\*.workloads.\*.updated_by.href | string |  |   /users/30 
action_result.data.\*.workloads.\*.ven.href | string |  |   /orgs/1/vens/bb558b7b-bd43-41f1-bdd9-e576728ca81b 
action_result.data.\*.workloads.\*.visibility_level | string |  |   flow_summary 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully fetched workloads 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create service binding'
Binds workload with virtual service

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**workload_hrefs** |  required  | List of workload HREFS (Comma-seperated values are allowed) | string |  `illumio workload href` 
**virtual_service_href** |  required  | Virtual service HREF | string |  `illumio virtual service href` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.virtual_service_href | string |  `illumio virtual service href`  |   /orgs/1/sec_policy/draft/virtual_service/958 
action_result.parameter.workload_hrefs | string |  `illumio workload href`  |   /orgs/1/sec_policy/draft/workload/958 
action_result.data.\*.errors.\*.status | string |  |   uniqueness_failure 
action_result.data.\*.service_bindings.\*.href | string |  |   /orgs/1/service_bindings/bffce2c8-d54c-4d43-8f0b-75e1af3d3b84 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully bound workload with virtual service 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update enforcement mode'
Update enforcement mode of workloads

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**workload_hrefs** |  required  | List of HREFs (Comma-seperated values are allowed) | string |  `illumio workload href` 
**enforcement_mode** |  required  | Enforcement mode to apply to the given Workloads | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.workload_hrefs | string |  `illumio workload href`  |   /orgs/1/workloads/c7098f30-8460-4873-a06c-8df87dc1ba1d 
action_result.parameter.enforcement_mode | string |  |   selective 
action_result.data.\*.\*.errors.\*.message | string |  |   Invalid URI: {/orgs/1/workloads/6ee0434b-46a8-48e3-b813-bdde9ccb1c} 
action_result.data.\*.\*.errors.\*.token | string |  |   invalid_uri 
action_result.data.\*.\*.href | string |  `illumio workload href`  |   /orgs/1/workloads/bd004cd5-f37c-4823-9ec9-cb1773dd11fc 
action_result.summary | string |  |  
action_result.message | string |  |   Successfully updated workloads 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
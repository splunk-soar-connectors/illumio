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

    -   This action tests the connectivity of the Splunk SOAR server to the Illumio instance by
        using the provided asset configuration parameters.
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

              
            .

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

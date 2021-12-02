# File: cymon_consts.py
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
CYMON_JSON_IP = "ip"
CYMON_JSON_DOMAIN = "domain"
CYMON_JSON_HASH = "hash"

CYMON_CONFIG_API_KEY = "api_key"

CYMON_BASE_API_URL = "https://cymon.io/api/"

CYMON_API_URI_IP_LOOKUP = "nexus/v1/ip/{addr}/"
CYMON_API_URI_IP_EVENTS = "nexus/v1/ip/{addr}/events/"
CYMON_API_URI_IP_DOMAINS = "nexus/v1/ip/{addr}/domains/"
CYMON_API_URI_IP_URLS = "nexus/v1/ip/{addr}/urls/"
CYMON_API_URI_IP_BLACKLIST = "nexus/v1/blacklist/ip/{addr}/"

CYMON_API_URI_DOMAIN_LOOKUP = "nexus/v1/domain/{name}"

CYMON_API_URI_URL_LOOKUP = "nexus/v1/url/{location}"

CYMON_API_URI_FILE_REPUTATION = "nexus/v1/malware/{hash}/events"

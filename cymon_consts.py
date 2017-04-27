# --
# File: cymon_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

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

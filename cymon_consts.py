# File: cymon_consts.py
# Copyright (c) 2016-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

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

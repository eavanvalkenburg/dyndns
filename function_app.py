"""Main function that runs when called with http request."""

import asyncio
import logging
import os

import azure.functions as func
from azure.core.exceptions import HttpResponseError
from azure.identity.aio import ManagedIdentityCredential
from azure.mgmt.dns.v2023_07_01_preview.aio import DnsManagementClient
from azure.mgmt.dns.v2023_07_01_preview.models import (
    ARecord,
    AaaaRecord,
    RecordSet,
    RecordType,
)

logger = logging.getLogger(__name__)

app = func.FunctionApp()

SUCCESS = "good {}"
NOCHANGE = "nochg {}"
UNAUTHORIZED = "badauth"
UPDATE_ERROR = "911"
NOZONE = "nohost"

HEADER_AUTH = "Authorization"
PARAM_HOSTNAME = "hostname"
PARAM_IP = "myip"
PARAM_IPV6 = "myipv6"

UPDATER_CREDENTIAL = "UpdaterCredential"
RESOURCE_GROUP = "ResourceGroup"
SUBSCRIPTION_ID = "SubscriptionId"


@app.function_name(name="dyndns")
@app.route(
    route="update_dns",
    methods=["GET", "POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
async def update_dns(req: func.HttpRequest) -> func.HttpResponse:
    """Code that reads the query and processes the dns changes."""
    logger.info("Requested url: %s", req.url)
    auth = req.headers.get(HEADER_AUTH)
    if auth is None:
        logger.warning("Unauthorized request, no auth header")
        return func.HttpResponse(UNAUTHORIZED)
    stored_auth = os.environ[UPDATER_CREDENTIAL]
    if not stored_auth.startswith("Basic "):
        stored_auth = f"Basic {stored_auth}"
    if auth != stored_auth:
        logger.warning("Unauthorized request, incorrect credentials")
        return func.HttpResponse(UNAUTHORIZED)

    hostname = req.params.get(PARAM_HOSTNAME)
    ip_address = req.params.get(PARAM_IP)
    ipv6_address = req.params.get(PARAM_IPV6)

    if not hostname or not (ip_address or ipv6_address):
        logger.warning("Missing hostname or ip address")
        logger.warning("Params: %s", req.params)
        logger.warning("Headers: %s", req.headers.__dict__)
        logger.warning("body: %s", req.get_body())
        logger.warning("route_params: %s", req.route_params)
        logger.warning("req: %s", req.__dict__)
        return func.HttpResponse(UPDATE_ERROR, status_code=500)

    if ip_address and "," in ip_address and not ipv6_address:
        ipv6_address = ip_address.split(",")[1]
        ipv4_address = ip_address.split(",")[0]
    else:
        ipv4_address = ip_address

    try:
        results = await update_dns_records(hostname, ipv4_address, ipv6_address)
    except ZoneException:
        return func.HttpResponse(NOZONE)
    except HttpResponseError as exc:
        logger.error("Other error in request, %s", exc)
        return func.HttpResponse(UPDATE_ERROR, status_code=500)
    if ipv4_address:
        if ipv6_address:
            ip_address = f"{ipv4_address},{ipv6_address}"
        else:
            ip_address = ipv4_address
    else:
        ip_address = ipv6_address
    response = [
        SUCCESS.format(ip_address) if res else NOCHANGE.format(ip_address)
        for res in results
    ]
    return func.HttpResponse("\n".join(response))


async def update_dns_records(
    hostnames: str, ipv4_address: str | None, ipv6_address: str | None
) -> list[bool]:
    """Update the dns records for the hostname."""
    rg = os.environ[RESOURCE_GROUP]
    subscription = os.environ[SUBSCRIPTION_ID]
    logger.info(
        f"Updating dns records for {hostnames} with ipv4: {ipv4_address}, and ipv6 {ipv6_address} in rg: {rg} and subscription: {subscription}"
    )
    try:
        async with (
            ManagedIdentityCredential() as cred,
            DnsManagementClient(
                credential=cred,
                subscription_id=subscription,
            ) as dns,
        ):
            zones = dns.zones.list_by_resource_group(resource_group_name=rg)
            async for zone in zones:
                logger.debug("Zone: %s", zone)
            return await asyncio.gather(
                *[
                    run_check_and_update(
                        dns,
                        rg,
                        hostname,
                        ipv4_address,
                        ipv6_address,
                    )
                    for hostname in hostnames.split(",")
                ]
            )
    except Exception as exc:
        logger.error("Error updating dns records: %s", exc)
        raise
    finally:
        await cred.__aexit__(None, None, None)


async def run_check_and_update(
    dns: DnsManagementClient,
    rg: str,
    hostname: str,
    ipv4_address: str | None,
    ipv6_address: str | None,
) -> bool:
    """Check for the record and update if needed."""
    record_name = hostname.split(".", 1)[0]
    zone_name = hostname.split(".", 1)[1]
    try:
        await dns.zones.get(rg, zone_name)
    except HttpResponseError as exc:
        raise ZoneException(f"Zone not found: {zone_name}") from exc

    changed = False
    if ipv4_address is not None:
        to_update = await record_to_update(
            dns, rg, zone_name, record_name, ipv4_address
        )
        if to_update:
            changed = await update_record(dns, rg, zone_name, record_name, ipv4_address)
    if ipv6_address is not None:
        to_update = await record_to_update(
            dns,
            rg,
            zone_name,
            record_name,
            ipv6_address,
            ipv6_flag=True,
        )
        if to_update:
            changed = await update_record(
                dns,
                rg,
                zone_name,
                record_name,
                ipv6_address,
                ipv6_flag=True,
            )
    return changed


async def update_record(
    dns: DnsManagementClient,
    rg: str,
    zone_name: str,
    record_name: str,
    ip_address: str,
    ipv6_flag: bool = False,
) -> bool:
    """Update the record."""
    if ipv6_flag:
        record_set = RecordSet(
            ttl=3600, aaaa_records=[AaaaRecord(ipv6_address=ip_address)]
        )
    else:
        record_set = RecordSet(ttl=3600, a_records=[ARecord(ipv4_address=ip_address)])
    logger.debug(
        "Updating record %s for zone %s and ip %s",
        record_name,
        zone_name,
        ip_address,
    )
    await dns.record_sets.create_or_update(
        resource_group_name=rg,
        zone_name=zone_name,
        relative_record_set_name=record_name,
        record_type=RecordType.AAAA if ipv6_flag else RecordType.A,
        parameters=record_set,
    )
    return True


async def record_to_update(
    dns: DnsManagementClient,
    rg: str,
    zone_name: str,
    record_name: str,
    ip_address: str | None,
    ipv6_flag: bool = False,
) -> bool:
    """Check if the record needs to be updated."""
    try:
        logger.debug(
            "Checking record %s for zone %s and ip %s",
            record_name,
            zone_name,
            ip_address,
        )
        record = await dns.record_sets.get(
            resource_group_name=rg,
            zone_name=zone_name,
            relative_record_set_name=record_name,
            record_type=RecordType.AAAA if ipv6_flag else RecordType.A,
        )
        logger.debug("Record: %s", record)
        if ipv6_flag:
            if (
                record.aaaa_records is not None
                and record.aaaa_records[0].ipv6_address != ip_address
            ):
                return True
            return False
        if (
            record.a_records is not None
            and record.a_records[0].ipv4_address != ip_address
        ):
            return True
        return False
    except HttpResponseError:
        logger.info("Record not found, creating")
        return True


class ZoneException(Exception):
    """Exception for when the zone is not found."""

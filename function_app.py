"""Main function that runs when called with http request."""
import logging
import os

import azure.functions as func
from azure.core.exceptions import HttpResponseError
from azure.identity.aio import DefaultAzureCredential
from azure.mgmt.dns.aio import DnsManagementClient
from azure.mgmt.dns.v2018_05_01.models import ARecord, RecordSet

app = func.FunctionApp()

SUCCESS = "good"
UNAUTHORIZED = "badauth"
UPDATE_ERROR = "dnserr"
NOZONE = "nohost"
NOCHANGE = "nochg"


@app.function_name(name="dyndns")
@app.route(
    route="update_dns",
    methods=["GET", "POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
async def update_dns(req: func.HttpRequest) -> func.HttpResponse:
    """Code that reads the query and processes the dns changes."""
    logging.info("Request: %s", req)

    auth = req.headers.get("Authorization")
    if auth is None:
        logging.info("Unauthorized request, no auth header")
        return func.HttpResponse(UNAUTHORIZED)
    basic_auth = auth.split(" ")[1]
    credential = basic_auth.decode("base64")
    logging.info("Credential: %s", credential)
    if credential != os.getenv("UpdaterCredential"):
        logging.info("Unauthorized request, incorrect credentials")
        return func.HttpResponse(UNAUTHORIZED)

    logging.warning("Request: %s", req)
    logging.warning("Route params: %s", req.route_params)
    # query = req.route_params.get("query")

    hostname = req.route_params.get("hostname")
    ip_address = req.route_params.get("myip")

    if not hostname or not ip_address:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            hostname = req_body.get("hostname")
            ip_address = req_body.get("myip")

    if not hostname or not ip_address:
        logging.info("Missing hostname or ip address")
        return func.HttpResponse(UPDATE_ERROR)

    try:
        changed = True
        # changed = await update_dns_records(hostname, ip_address)
    except ZoneException:
        logging.error("Zone not found")
        return func.HttpResponse(NOZONE)
    except HttpResponseError as exc:
        logging.error("Other error in request, %s", exc)
        return func.HttpResponse(UPDATE_ERROR)
    return func.HttpResponse(SUCCESS if changed else NOCHANGE)


async def update_dns_records(hostname: str, ip_address: str) -> bool:
    """Update the dns records for the hostname."""
    # Replace this with your subscription id
    subscription_id = os.environ["SubscriptionId"]
    resource_group = os.environ["ResourceGroup"]

    # split hostname into zone and record name
    record_name = hostname.split(".", 1)[0]
    zone_name = hostname.split(".", 1)[1]

    async with DefaultAzureCredential() as credential:
        async with DnsManagementClient(
            credential=credential,
            subscription_id=subscription_id,
        ) as dns_client:
            # get the zone
            zone = await dns_client.zones.get(
                resource_group_name=resource_group, zone_name=zone_name
            )
            if not zone:
                # zone doesn't exist, unable to update
                raise ZoneException("Zone not found")
            record = await dns_client.record_sets.get(
                resource_group_name=resource_group,
                zone_name=zone_name,
                relative_record_set_name=record_name,
                record_type="A",
            )
            if (
                record
                and record.a_records is not None
                and record.a_records[0].ipv4_address == ip_address
            ):
                return False
            await dns_client.record_sets.create_or_update(
                resource_group_name=resource_group,
                zone_name=zone_name,
                relative_record_set_name=record_name,
                record_type="A",
                parameters=RecordSet(
                    ttl=3600, a_records=[ARecord(ipv4_address=ip_address)]
                ),
            )
            return True


class ZoneException(Exception):
    """Exception for when the zone is not found."""

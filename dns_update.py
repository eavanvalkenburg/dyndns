# """The code that communicates with Azure."""

# import os

# from azure.identity.aio import DefaultAzureCredential
# from azure.mgmt.dns.aio import DnsManagementClient
# from azure.mgmt.dns.v2018_05_01.models import ARecord, RecordSet


# async def update_dns_records(hostname: str, ip_address: str) -> bool:
#     """Update the dns records for the hostname."""
#     # Replace this with your subscription id
#     subscription_id = os.environ["SubscriptionId"]
#     resource_group = os.environ["ResourceGroup"]

#     # split hostname into zone and record name
#     record_name = hostname.split(".", 1)[0]
#     zone_name = hostname.split(".", 1)[1]

#     async with DefaultAzureCredential() as credential:
#         async with DnsManagementClient(
#             credential=credential,
#             subscription_id=subscription_id,
#         ) as dns_client:
#             # get the zone
#             zone = await dns_client.zones.get(
#                 resource_group_name=resource_group, zone_name=zone_name
#             )
#             if not zone:
#                 # zone doesn't exist, unable to update
#                 raise ZoneException("Zone not found")
#             record = await dns_client.record_sets.get(
#                 resource_group_name=resource_group,
#                 zone_name=zone_name,
#                 relative_record_set_name=record_name,
#                 record_type="A",
#             )
#             if (
#                 record
#                 and record.a_records is not None
#                 and record.a_records[0].ipv4_address == ip_address
#             ):
#                 return False
#             await dns_client.record_sets.create_or_update(
#                 resource_group_name=resource_group,
#                 zone_name=zone_name,
#                 relative_record_set_name=record_name,
#                 record_type="A",
#                 parameters=RecordSet(
#                     ttl=3600, a_records=[ARecord(ipv4_address=ip_address)]
#                 ),
#             )
#             return True


# class ZoneException(Exception):
#     """Exception for when the zone is not found."""

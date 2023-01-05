# Dynamics DNS through Azure Functions to Azure DNS
This is a simple Azure Function that will update an Azure DNS zone based on the NOIP dynamic DNS. 

This has been tested with a Unifi Network controller, but should work with any device that supports dynamic DNS according to the way [noip](https://www.noip.com/integrate/request) does it. It uses basic authentication to authenticate the request and sets the A record for the hostname to the IP address of the request.

## Setup
Azure setup: 
1. Create a new Azure Function App
2. Deploy the function
3. Set the following settings in the Function app:
   1. "UpdaterCredential": "username:password",
   1. "SubscriptionId": "subscription where the DNS zone is located",
   1. "ResourceGroup": "resource group where the DNS zone is located"
4. Turn on system assigned managed identity for the function app and give it the "DNS Zone Contributor" role on the DNS zone you want it to update

In Unify Network Controller:
1. Go to Internet/WAN settings, under Dynamics DNS:
   1. Service: noip
   2. Hostname: the format is `name.zone`, and it can include '@' as the name, for instance `@.azure.com`
   3. Username: the username you set in the function app
   4. Password: the password you set in the function app
   5. Server: the function URL you get after deployment, without https and with a `?hostname=%h&myip=%i` at the end, so `functionname.azurewebsites.net/api/update_dns?hostname=%h&myip=%i`. The inadyn package replaces the `%h` with the hostname and `%i` with the IP address.
2. Done!

### Troubleshooting
Unifi controller, or at least the Network application on the Dream Router, uses [inadyn](https://github.com/troglobit/inadyn).

If you ssh into your Unify controller, you can see the logs by running `cat /var/log/messages | grep inadyn`

Alternatively, you can run on your Unify controller:
`cat /run/ddns-eth4-inadyn.conf` on your Unify controller to see the configuration file for the dynamic DNS. It should look something like this:
```
#
# Generated automatically by ubios-udapi-server
#
iface = eth4

custom functionname.azurewebsites.net:1 {
    hostname = "@.azure.com"
    username = "username"
    password = "password"
    ddns-server = "functionname.azurewebsites.net"
    ddns-path = "/api/update_dns?hostname=%h&myip=%i"
}
```

## Final notes

This should also work with other Unify systems and potentially other devices that support dynamic DNS, it fully implements the features described at noip, including double-stacking (sending both ipv4 and ipv6 seperated with a comma), myipv6 and multiple hostnames. 

The overall approach is based on: [this blog post](https://blog.nielsb.net/dynamic-dns-with-edgerouter-and-azure) by [Niels Buit](https://github.com/nielsams), who deserves many credits!

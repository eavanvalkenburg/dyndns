# Dynamics DNS through Azure Functions to Azure DNS
This is a simple Azure Function that will update an Azure DNS zone based on the NOIP dynamic DNS. 

This has been tested with a Unifi Network controller, but should work with any device that supports dynamic DNS according to the way NOIP does it. It uses basic authentication to authenticate the request and sets the A record for the hostname to the IP address of the request.

## Setup
1. Create a new Azure Function App
2. Deploy the function
3. Set the following settings in the Function app:
   1. "UpdaterCredential": "username:password",
   1. "SubscriptionId": "subscription where the DNS zone is located",
   1. "ResourceGroup": "resource group where the DNS zone is located",

In Unify Network Controller, set the following settings:
Go to Internet/WAN settings, under Dynamics DNS:
1. Service: noip
2. Hostname: the format is `name.zone`, and it can include '@' as the name, for instance `@.azure.com`
3. Username: the username you set in the function app
4. Password: the password you set in the function app
5. Server: the function URL you get after deployment, without https and with a `?` at the end, so `functionname.azurewebsites.net/api/update_dns?`

Test and see!

If you ssh into your Unify controller, you can see the logs by running `cat /var/log/messages | grep inadyn`

This should also work with otehr Unify systems and potentially other devices that support dynamic DNS. It is based on: [this blog post](https://blog.nielsb.net/dynamic-dns-with-edgerouter-and-azure) by [Niels Buit](https://github.com/nielsams).

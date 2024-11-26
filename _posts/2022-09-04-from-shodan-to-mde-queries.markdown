---
layout: post
title:  "From Shodan to MDE queries"
tags: [defender for endpoint, shodan]
author: jouni
image: assets/images/shodan_to_mde.png
comments: false
categories: [ threat hunting ]
---

I've had an idea for some time for using the Shodan and MDE API:s. The idea is to pull recently identified C2 servers from Shodan and use the IP-addresses to run a query against the MDE API. This could then be automated to be ran on a daily basis, for example. As I didn't want to use too much time on developing this thing, I used code made by others. Also, I am not very skilled in Python so there are likely many things that could be done much more efficiently, or better. The solution is pictured in the following diagram.

![]({{ site.baseurl }}/assets/images/shodan_to_mde.png)

Starting with Shodan, I stumbled upon an article containing queries to hunt for certain type of C2 server. This included Cobalt Strike, Posh, Deimos and Empire. Some of the queries are very noisy so I only picked the ones that are stated to be non FP sensitive. The queries are available here: [https://cyberwarzone.com/shodan-queries-list-for-threat-hunters-2022/](https://cyberwarzone.com/shodan-queries-list-for-threat-hunters-2022/). Starting the Python script by the required imports (which should be installed with pip if missing): shodan, pandas, json, urllib, datetime. Then, setting the Pandas Dataframe show options so that all the data is shown, however with the current version the data is actually saved to a JSON file. Showing it in a table format is nice with Jupyter  which I often use and thus I tend to go for PD approach, even when not exactly needed.

The second part is important. The API key for Shodan and Defender for Endpoint are added here. MDE requires you to create your own API key, instructions are here: [https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide). **Remember, you need to add API permissions to run "read" advanced hunt which is not stated in the instructions**. With, Shodan, the API key can be seen under the account settings.

    # API_keys
    # These are a must to have for the script to work.
    #Define Shodan, authenticate with the API key
    shodanapi = Shodan('your_shodan_api_key')
    
    #Defender API keys
    Client_id = "your_client_ID"
    Client_secret = "your_client_secret"
    TenantId = "your_tenant_id"
    

The script is built using the shodan-python, which allows for easy access to the Shodan API  with Python. I created a function which allows for running any query from Shodan, dropping results dating back more than 7 days. The API results only the latest page, so basically the 100 newest results. This only goes through the latest page. It wouldn't be hard to go through the pages but it would add quite a lot of addresses to look with the Defender API. Also, my Shodan API calls are fairly limited, so I didn't want to add the overhead.

After querying Shodan for the information the script will add the addresses in a format that can be passed to a query that is then sent to Defender API.

    def run_shodan_query_return_IP_filter(query):
        try:
            data = shodanapi.search(query)
            QueryFilter = "("
            for a in data['matches']:
                # Set the format for the timestamp
                format = "%Y-%m-%dT%H:%M:%S.%f"
                #Change the string format of the timestamp as datetime format
                IPDateTime = datetime.datetime.strptime(a['timestamp'],format)
                #Only return results where the IP address was detected less than 7 days ago
                if IPDateTime > datetime.datetime.now() - timedelta(7):
                    QueryFilter = QueryFilter + "'" + a['ip_str'] + "',"
            l = len(QueryFilter)
            QueryFilter = QueryFilter[:l-1]
            QueryFilter = QueryFilter + ")"
            if QueryFilter = ")":
                print("No results for the query : " + query)
                QueryFilter = ""
            return QueryFilter
        except Exception as e:
            print('Error: %s' % e)
    

Then, I added the queries I'd like to run in a dict. As you can see, the MDE queries are stated within the dict. This is the part you need to modify when adding your own queries.

    #Add the filters to a dict
    queries = {
        'CobaltStrikeJARMfilter': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("ssl.jarm:07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2")}',
        'CobaltStrikeProductName': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""product:"Cobalt Strike Beacon" """)}',
        'PoshC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""ssl:"P18055077" """)}',
        'EmpireC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("""product:"Empire C2" """)}',
        'DeimosC2': f'DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteIP in {run_shodan_query_return_IP_filter("http.html_hash:-14029177")}'
    }
    

The MDE authentication is handled by scripts created by Microsoft, available here: [https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Notebooks/M365D%20APIs%20ep3.ipynb](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Notebooks/M365D%20APIs%20ep3.ipynb). No need to redo something that is already working, in my opinion. I won't describe that part much more in this post.

Next, is the actual code which is running the queries against the Defender API and return the results as json files. The query will loop through the keys in the queries dict and as the query itself is stored as a value that will be used to run the actual query. The key name will be used as the name of the JSON file and it will be saved to the current working directory.

    #Run the queries stored in the queries dict, one by one.
    for a in queries:
        if queries[a].endswith(")"):
            df = exec_mtp_query(queries[a],aadToken)
            if df.empty == False:
                #write the results to a json file in the working directory.
                filename = a+".json"
                jsonfile=df.to_json(orient="split")
                with open(filename,'w') as f:
                    f.write(jsonfile)
                    f.close()
    

This is pretty much it. It seems to work as intended although no results were found from my testing environment. This is very simple script which needs some tinkering to be more "production ready". However, as a quick and dirty script to look for recently popped up C2 servers it works nicely. With better error-handling and using some sort of password manager solution to store the secrets this could be made much more elaborate. Also, the Shodan queries are to be taken as more of an example. I have no idea how efficient these actually are in finding true-positive C2 servers.

The script is available here: [https://github.com/JouniMi/Threathunt.blog/blob/main/shodan\_to\_mde.py](https://github.com/JouniMi/Threathunt.blog/blob/main/shodan_to_mde.py)
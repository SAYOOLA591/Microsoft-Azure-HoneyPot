# Start a Workbook

Navigate to Microsoft Sentinel → select your workspace

Under Threat Management, click on Workbooks

Select "Add Workbook", then click Edit to begin customization

# Remove the default title or replace it as needed

🌍 Failed SSH Logon Map (Linux)

🧭 Setup Visual Map

# Use the saved failed logon query

 Change visualization to Map
 
 Use Geo_info_from_ip_address() to get latitude, longitude, and country
 Use summarize count by to aggregate hits by country
# Configure Map

In Map Settings:

Latitude field → latitude

Longitude field → longitude

Color settings → Heat Map

Metric label → country

Metric value → count

Save visual and name it "Failed SSH Logon Attempts".

##

## Note: Continue To Add more queries for all following Logon Types

## Related Querie:

Failed SSH Logon 

```kql

CowrieLog_CL
| where RawData has "login attempt" and RawData !has "succeeded"
| extend
    Timestamp = extract(@"^(\d{4}-\d{2}-\d{2}T[^Z]+Z)", 1, RawData),
    SrcIP = extract(@"\[(?:[^,]+),\d+,(\d+\.\d+\.\d+\.\d+)\]", 1, RawData),
    Username = extract(@"login attempt \[b'([^']+)'", 1, RawData),
    Password = extract(@"\/b'([^']+)'\]", 1, RawData),
    AuthMethod = extract(@"auth b'([^']+)'", 1, RawData),
    Status = "failure" 
| extend ip_location=geo_info_from_ip_address(SrcIP)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country
| summarize count() by tostring(country), tostring(latitude), tostring(longitude)
| top 10 by count_
```

Successful SSH Logons

```kql

CowrieLog_CL
| where RawData has "login attempt" and RawData has "succeeded"
| extend
    Timestamp = extract(@"^(\d{4}-\d{2}-\d{2}T[^Z]+Z)", 1, RawData),
    SrcIP = extract(@"\[(?:[^,]+),\d+,(\d+\.\d+\.\d+\.\d+)\]", 1, RawData),
    Username = extract(@"login attempt \[b'([^']+)'", 1, RawData),
    Password = extract(@"\/b'([^']+)'\]", 1, RawData),
    AuthMethod = extract(@"auth b'([^']+)'", 1, RawData),
    Status = "succeeded", "success"
    | extend ip_location=geo_info_from_ip_address(SrcIP)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country
| summarize count() by tostring(country), tostring(latitude), tostring(longitude)
| top 10 by count_
```

Successful SSH Logon by User

```kql

CowrieLog_CL
| where RawData has "login attempt" and RawData has "succeeded"
| extend
    Timestamp = extract(@"^(\d{4}-\d{2}-\d{2}T[^Z]+Z)", 1, RawData),
    SrcIP = extract(@"\[(?:[^,]+),\d+,(\d+\.\d+\.\d+\.\d+)\]", 1, RawData),
    Username = extract(@"login attempt \[b'([^']+)'", 1, RawData),
    Password = extract(@"\/b'([^']+)'\]", 1, RawData),
    AuthMethod = extract(@"auth b'([^']+)'", 1, RawData),
    Status = "succeeded", "success"
    | extend ip_location=geo_info_from_ip_address(SrcIP)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country

| summarize count() by tostring(country),Username, SrcIP
| top 10 by count_
```

Successful Windows Logon by User

```kql

Event 
| where EventID == 4624
|extend event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[18].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[8].["#text"])
| extend ip_location=geo_info_from_ip_address(src_ip)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country
| summarize count() by tostring(country), username, src_ip
| top 10 by count_
```

Failed Windows Logon

```kql

Event 
| where EventID == 4625
| extend event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[19].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[10].["#text"])
| extend ip_location=geo_info_from_ip_address(src_ip)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country
| summarize count() by tostring(country), tostring(latitude), tostring(longitude)
| top 10 by count_
```

Successful Windows Logon

```kql

Event 
| where EventID == 4624
|extend event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[18].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[8].["#text"])
| extend ip_location=geo_info_from_ip_address(src_ip)
| extend latitude = ip_location.latitude
| extend longitude = ip_location.longitude
| extend country = ip_location.country
| summarize count() by tostring(country), tostring(latitude), tostring(longitude)
| top 10 by count_
```
##

# OpenipTr4ckin9    

## Description
If your system has been attacked and hacked, all of attacks are logged at your system. </br>
at least, attacker's software (backdoor tools etc) are still installed when you pull off your plug. </br>

Those attacks necessarily include the attacker's IP address. and GeoIP DataBase have ISP(Internet Service Provider)'s Latitude and Longitude. If System manager find some data about Attackers trace, This Program might useful for international legal litigation. 

So, OpenIpTr4ck3r's purpose is "Find attackers Physical location using IP Addr  ",
like Country name, Longitude, Langitude.

## ScreenShot
* * *

## Usage
* * *

```python
  $python OpenipTr4ck3r.py {destination ip address}
```

## Requirments

```python
  - Python 2.7
  - pyGeoIp
```
+==========================================+  
https://pypi.python.org/pypi/pygeoip    
+==========================================+    

## Recent Update Issues
* * *
+ pygeoip - lastest version => 0.3.2    


## Warning
* * *
**You may need some modifications to drive this script.**  
Within the source code, the default path for the database is : ('C:\ Python27 \ GeoDB \ GeoLiteCity.dat')  
If you put the file in the Python basic installation path, you won't need a separate modifications.  
**To run in your system specific directory, you need to modify the database path.**      

# bro_intel_linter
Bro Intel Feed Linter
The bro_intel_linter was built to verify all the appropriate header delineation and mandatory field verification, tab separation, correlation of indicator and indicator_type. 

## Usage
    intel_linter.py -f <file.intel>
  
## Example

### Example File

Test File:
~~~
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url	meta.do_notice	meta.if_in	meta.whitelist	meta.severity
192.168.1.1	Intel::ADDR	my imagination	ADDR	-	F	-	-	6
192.168.1.2	Intel::ADDR	my imagination	ADDR	-	F	-	-	6
192.168.1.300	Intel::ADDR	my imagination	ADDR	-	F	-	-	6
~~~

Result:
~~~
WARNING: Line 4 - Indicator type "Intel::ADDR" does not correlate with indicator: "192.168.1.300"
~~~

A clean execution means the intelligence file supplied passed all lint testing.

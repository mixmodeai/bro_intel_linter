![PacketSled Logo](https://packetsled.com/wp-content/themes/freshbiz/img/packetsled-logo.png)
# Bro Intel Feed Linter
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

# License

GPL

Copyright (c) 2015, Packetsled. All rights reserved.

bro_intel_linter is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

bro_intel_linter is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with bro_intel_linter.  If not, see <http://www.gnu.org/licenses/>.

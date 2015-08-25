# bro_intel_linter
Bro Intel Feed Linter
The bro_intel_linter was built to verify all the appropriate tab separation, naming and verification of the single character fields ('-', 'T', 'F').

## Usage
    intel_linter.py --file=<file.intel>
  
## Example

### Example File

Test File:
~~~
#fields indicator       indicator_type  meta.source     meta.url        meta.do_notice  meta.if_in      meta.whitelist  meta.desc
192.168.1.1     Intel::ADDR     Some kind of intelligent system -       F       -       -       Router
192.168.1.2     Intel::ADDR     Some kind of intelligent system -       F       _       -       Firewall
192.168.1.3     Intel::ADDR     Some kind of intelligent system -       F       -       -       You don't want to know
~~~

Result:
~~~
WARNING: Line 3 - Invalid single character field entry, offset [5]
~~~

A clean execution means the intelligence file supplied passed all lint testing.

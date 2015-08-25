#!/usr/bin/python
#
# PacketSled - Bro Intel Linter
#
# WHEN          WHAT                                               WHO
# 3-4-2015      Initial development                                Aaron Eppert
# 8-24-2015     Explicitly verify single character fields          Aaron Eppert
# 8-24-2015     GPL and pushed to GitHub                           Aaron Eppert
# 8-25-2015     Small cleanups and proper exit codes for using
#               as a git pre-commit hook                           Aaron Eppert
#
import sys
import re
from optparse import OptionParser


def warning(msg):
    sys.stderr.write(msg + '\n')


def warning_line(line, *objs):
    out = 'WARNING: Line %d - ' % (int(line)+1)
    for o in objs:
        out += o
    warning(out)


class bro_intel_feed_verifier:
    required_fields = ['indicator',
                       'indicator_type',
                       'meta.source',
                       'meta.desc']
    field_header_designator = '#fields'
    feed_rx = r'([\S]+)'
    feed_sep_rx = r'(\t)+'

    def __init__(self, feed_file):
        self.feed_file = feed_file
        self.__feed_header_found = False
        self.__num_of_fields = 0

    def __make_one_indexed(self, l):
        return map(lambda x: x+1, l)

    def __is_start_of_feed(self, l):
        ret = False
        if len(l) >= 2:
            if l[0] == self.field_header_designator:
                ret = True
        return ret

    def __are_header_fields_valid(self, l):
        ret = False
        _fields_found = []
        if l[0] == self.field_header_designator:
            for index, item in enumerate(l):
                if index == 0:
                    continue
                if item in self.required_fields:
                    _fields_found.append(item)

            t_list_diff = list(set(self.required_fields) - set(_fields_found))
            if len(t_list_diff) == 0:
                ret = True
            else:
                warning_line(0, 'Fields missing: %s' % (','.join(t_list_diff)))
        return ret

    def __count_fields(self, l):
        return (len(l) - 1)

    ##
    # <0 - Too few fields
    #  0 - Proper field count
    # >0 - Too many fields
    ##
    def __verify_field_count(self, l):
        return (len(l) - self.__num_of_fields)

    def __verify_non_space(self, offset, l):
        ret = True

        r = [i for i, x in enumerate(l) if x == ' ']
        if len(r) > 0:
            warning_line(offset, 'Invalid empty field, offset %s' % (self.__make_one_indexed(r)))
            ret = False
        return ret

    def __verify_single_char_entry(self, offset, l):
        val = ['-', 'T', 'F']
        ret = True
        r = [i for i, x in enumerate(l) if (len(x) == 1 and x not in val)]
        if len(r) > 0:
            warning_line(offset, 'Invalid single character field entry, offset %s' % (self.__make_one_indexed(r)))
            ret = False
        return ret

    def __get_field_contents(self, l):
        return l.split('\t')

    def __verify_field_sep(self, offset, l, is_header=False):
        ret = True
        field_seps = re.findall(self.feed_sep_rx, l, re.IGNORECASE)
        __field_total = self.__num_of_fields

        if is_header:
            __field_total += 1

        if len(field_seps) >= __field_total:
            warning_line(offset, 'Excess field separators found')
            ret = False

        for index, item in enumerate(field_seps):
            for s in item:
                if s != '\t':
                    warning_line(offset, 'Field separator incorrect in field offset %d' % (self.__make_one_indexed(index)))
                    ret = False
        return ret

    def __verify_header(self, index, l):
        ret = False
        contents = self.__get_field_contents(l)
        if self.__is_start_of_feed(contents) and self.__are_header_fields_valid(contents):
            if not self.__feed_header_found:
                self.__num_of_fields = self.__count_fields(contents)
                if self.__verify_field_sep(index, l, is_header=True):
                    ret = True
                    self.__feed_header_found = True
                else:
                    warning("Invalid field separator found in header. Must be a tab.")
            else:
                warning_line(index, "Duplicate header found")
        return ret

    def __verify_entry(self, index, l):
        ret = False
        contents = self.__get_field_contents(l)
        if self.__verify_field_count(contents) == 0:
            if self.__verify_field_sep(index, l) and self.__verify_non_space(index, contents) and self.__verify_single_char_entry(index, contents):
                ret = True
        else:
            warning_line(index, 'Invalid number of fields - Found: %d, Header Fields: %d - Verify EMPTY fields' %
                         (len(contents), self.__num_of_fields))
        return ret

    def __load_feed(self, feed):
        with open(feed) as f:
            for line in f:
                t_line = line.rstrip('\n')
                if len(t_line):
                    yield t_line

    def verify(self):
        for index, l in enumerate(self.__load_feed(self.feed_file)):
            # Check the header
            if index == 0:
                if not self.__verify_header(index, l):
                    warning_line(index, "Invalid header")
                    sys.exit(2)
            else:
                if not self.__verify_entry(index, l):
                    sys.exit(3)


def main():
    parser = OptionParser()
    parser.add_option('--file', dest='feed_file', help='Bro Intel Feed to Verify')
    (options, args) = parser.parse_args()

    for o in options.__dict__.keys():
        if not options.__dict__[o]:
            print 'Error: %s not specified' % (o)
            parser.print_help()
            sys.exit(1)

    bifv = bro_intel_feed_verifier(options.feed_file)
    bifv.verify()

if __name__ == '__main__':
    main()

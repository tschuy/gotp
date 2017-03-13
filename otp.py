#!/usr/bin/env python2

import pyotp
from datetime import datetime

print datetime.now().strftime('%Y-%m-%d %H:%M:%S')

cotp    = pyotp.TOTP("ZVB267QPFBAGROTDE6US5UN255A5BJAOKAJY2VMU3EZWNYCGKBLIVLJ3QB6N6GWR")
print "Test:       %06s" % cotp.now()

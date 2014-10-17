dnl build configuration for libmilter with libbind under x86_64 architecture

define(`confLIBDIRS', `-L/lib64 -L/usr/lib64')

define(`confINCLUDEDIR', `/path/to/libmilter_basedir/include')
define(`confLIBDIR', `/path/to/libmilter_basedir/lib')

APPENDDEF(`confINCDIRS', `-I/path/to/libbind_basedir/include/bind')
APPENDDEF(`confLIBS', `/path/to/libbind_basedir/lib/libbind.a')

APPENDDEF(`confENVDEF', `-DSM_CONF_POLL=1 -DNETINET6=1 -DNEEDSGETIPNODE=0')
APPENDDEF(`confOPTIMIZE', `-g')

dnl build configuration for libmilter with libbind under i386 architecture

define(`confINCLUDEDIR', `/path/to/libmilter_basedir/include')
define(`confLIBDIR', `/path/to/libmilter_basedir/lib')

APPENDDEF(`confINCDIRS', `-I/path/to/libbind_basedir/include/bind')
APPENDDEF(`confLIBS', `/path/to/libbind_basedir/lib/libbind.a')

APPENDDEF(`confENVDEF', `-DSM_CONF_POLL=1 -DNETINET6=1 -DNEEDSGETIPNODE=0')
APPENDDEF(`confOPTIMIZE', `-g')

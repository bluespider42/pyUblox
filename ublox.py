#!/usr/bin/env python
"""
UBlox binary protocol handling

Copyright Andrew Tridgell, October 2012
Released under GNU GPL version 3 or later

Modified Ben Pitcairn, 2016
"""

import struct
from datetime import datetime
import time
import os

# protocol constants
PREAMBLE1 = 0xb5
PREAMBLE2 = 0x62

# message classes
CLASS_NAV = 0x01
CLASS_RXM = 0x02
CLASS_INF = 0x04
CLASS_ACK = 0x05
CLASS_CFG = 0x06
CLASS_UPD = 0x09
CLASS_MON = 0x0A
CLASS_AID = 0x0B
CLASS_TIM = 0x0D
CLASS_ESF = 0x10
CLASS_MGA = 0x13
CLASS_LOG = 0x21
CLASS_SEC = 0x27

# ACK messages
MSG_ACK_NACK = 0x00
MSG_ACK_ACK = 0x01

# NAV messages
MSG_NAV_POSECEF = 0x01
MSG_NAV_POSLLH = 0x02
MSG_NAV_STATUS = 0x03
MSG_NAV_POSUTM = 0x8  # TODO check if still in spec
MSG_NAV_VELNED = 0x12
MSG_NAV_VELECEF = 0x11
MSG_NAV_TIMEGPS = 0x20
MSG_NAV_TIMEUTC = 0x21
MSG_NAV_CLOCK = 0x22
MSG_NAV_SVINFO = 0x30
MSG_NAV_AOPSTATUS = 0x60
MSG_NAV_DGPS = 0x31
MSG_NAV_DOP = 0x04
MSG_NAV_EOE = 0x61
MSG_NAV_GEOFENCE = 0x39
MSG_NAV_ODO = 0x09
MSG_NAV_ORB = 0x34
MSG_NAV_PVT = 0x07
MSG_NAV_RESETODO = 0x10
MSG_NAV_SAT = 0x35
MSG_NAV_EKFSTATUS = 0x40
MSG_NAV_SBAS = 0x32
MSG_NAV_SOL = 0x06
MSG_NAV_SVINFO = 0x30
MSG_NAV_TIMEBDS = 0x24
MSG_NAV_TIMEGAL = 0x25
MSG_NAV_TIMEGLO = 0x23
MSG_NAV_TIMELS = 0x26

# RXM messages
MSG_RXM_IMES = 0x61
MSG_RXM_MEASX = 0x14
MSG_RXM_RAW = 0x10  # TODO check if still in spec
MSG_RXM_SFRB = 0x11  # TODO check if still in spec
MSG_RXM_SVSI = 0x20
MSG_RXM_EPH = 0x31  # TODO check if still in spec
MSG_RXM_ALM = 0x30  # TODO check if still in spec
MSG_RXM_PMREQ = 0x41
MSG_RXM_RAWX = 0x15
MSG_RXM_RLM = 0x59
MSG_RXM_SFRBX = 0x13

# AID messages
MSG_AID_ALM = 0x30
MSG_AID_EPH = 0x31
MSG_AID_ALPSRV = 0x32  # TODO check if still in spec
MSG_AID_AOP = 0x33
MSG_AID_DATA = 0x10
MSG_AID_ALP = 0x50
MSG_AID_DATA = 0x10
MSG_AID_HUI = 0x02
MSG_AID_INI = 0x01
MSG_AID_REQ = 0x00  # TODO check if still in spec

# CFG messages
MSG_CFG_ANT = 0x13
MSG_CFG_CFG = 0x09
MSG_CFG_DAT = 0x06
MSG_CFG_DOSC = 0x61
MSG_CFG_DYNSEED = 0x85
MSG_CFG_ESRC = 0x60
MSG_CFG_FIXSEED = 0x84
MSG_CFG_GEOFENCE = 0x69
MSG_CFG_GNSS = 0x3E
MSG_CFG_EKF = 0x12  # TODO check if still in spec
MSG_CFG_ESFGWT = 0x29  # TODO check if still in spec
MSG_CFG_SET_RATE = 0x01  # TODO check if still in spec
MSG_CFG_FXN = 0x0E  # TODO check if still in spec
MSG_CFG_INF = 0x02
MSG_CFG_ITFM = 0x39
MSG_CFG_LOGFILTER = 0x47
MSG_CFG_MSG = 0x01
MSG_CFG_NAV5 = 0x24
MSG_CFG_NAVX5 = 0x23
MSG_CFG_NMEA = 0x17
MSG_CFG_ODO = 0x1E
MSG_CFG_NVS = 0x22  # TODO check if still in spec
MSG_CFG_PM2 = 0x3B
MSG_CFG_PMS = 0x86
MSG_CFG_PM = 0x32  # TODO check if still in spec
MSG_CFG_PRT = 0x00
MSG_CFG_PWR = 0x57
MSG_CFG_RATE = 0x08
MSG_CFG_RINV = 0x34
MSG_CFG_RST = 0x04
MSG_CFG_RXM = 0x11
MSG_CFG_SBAS = 0x16
MSG_CFG_SMGR = 0x62
MSG_CFG_TMODE2 = 0x3D
MSG_CFG_TMODE = 0x1D  # TODO check if still in spec
MSG_CFG_TP5 = 0x31
MSG_CFG_TP = 0x07  # TODO check if still in spec
MSG_CFG_TXSLOT = 0x53
MSG_CFG_USB = 0x1b

# ESF messages
MSG_ESF_MEAS = 0x02  # TODO check if still in spec
MSG_ESF_STATUS = 0x10

# INF messages
MSG_INF_DEBUG = 0x04
MSG_INF_ERROR = 0x00
MSG_INF_NOTICE = 0x02
MSG_INF_TEST = 0x03
MSG_INF_WARNING = 0x01

# LOG messages
MSG_LOG_CREATE = 0x07
MSG_LOG_ERASE = 0x03
MSG_LOG_FINDTIME = 0x0E
MSG_LOG_INFO = 0x08
MSG_LOG_RETRIEVEPOSEXTRA = 0x0f
MSG_LOG_RETRIEVEPOS = 0x0b
MSG_LOG_RETRIEVESTRING = 0x0d
MSG_LOG_RETRIEVE = 0x09
MSG_LOG_STRING = 0x04

# MGA messages
MSG_MGA_ACK = 0x60
MSG_MGA_ANO = 0x20
MSG_MGA_BDS = 0x03
MSG_MGA_DBD = 0x80
MSG_MGA_FLASH = 0x21
MSG_MGA_GAL = 0x02
MSG_MGA_GLO = 0x06
MSG_MGA_GPS = 0x00
MSG_MGA_INI = 0x40
MSG_MGA_QZSS = 0x05

# MON messages
MSG_MON_GNSS = 0x28
MSG_MON_SCHD = 0x01  # TODO check if still in spec
MSG_MON_HW = 0x09
MSG_MON_HW2 = 0x0B
MSG_MON_IO = 0x02
MSG_MON_MSGPP = 0x06
MSG_MON_PATCH = 0x27
MSG_MON_RXBUF = 0x07
MSG_MON_RXR = 0x21
MSG_MON_SMGR = 0x2E
MSG_MON_TXBUF = 0x08
MSG_MON_VER = 0x04

# SEC messages
MSG_SEC_SIGN = 0x01
MSG_SEC_UNIQID = 0x03

# TIM messages
MSG_TIM_TP = 0x01
MSG_TIM_TM2 = 0x03
MSG_TIM_SVIN = 0x04
MSG_TIM_VRFY = 0x06
MSG_TIM_DOSC = 0x11
MSG_TIM_FCHG = 0x16
MSG_TIM_HOC = 0x17
MSG_TIM_SMEAS = 0x13
MSG_TIM_TOS = 0x12
MSG_TIM_VCOCAL = 0x15

# UPD messages
MSG_UDP_SOS = 0x14

# port IDs
PORT_DDC = 0
PORT_SERIAL1 = 1
PORT_SERIAL2 = 2
PORT_USB = 3
PORT_SPI = 4

# dynamic models
DYNAMIC_MODEL_PORTABLE = 0
DYNAMIC_MODEL_STATIONARY = 2
DYNAMIC_MODEL_PEDESTRIAN = 3
DYNAMIC_MODEL_AUTOMOTIVE = 4
DYNAMIC_MODEL_SEA = 5
DYNAMIC_MODEL_AIRBORNE1G = 6
DYNAMIC_MODEL_AIRBORNE2G = 7
DYNAMIC_MODEL_AIRBORNE4G = 8

# reset items
RESET_HOT = 0
RESET_WARM = 1
RESET_COLD = 0xFFFF

RESET_HW = 0
RESET_SW = 1
RESET_SW_GPS = 2
RESET_HW_GRACEFUL = 4
RESET_GPS_STOP = 8
RESET_GPS_START = 9


class UBloxError(Exception):
    """Ublox error class"""

    def __init__(self, msg):
        Exception.__init__(self, msg)
        self.message = msg


class UBloxAttrDict(dict):
    """allow dictionary members as attributes"""

    def __init__(self):
        dict.__init__(self)

    def __getattr__(self, name):
        try:
            return self.__getitem__(name)
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if self.__dict__.has_key(name):
            # allow set on normal attributes
            dict.__setattr__(self, name, value)
        else:
            self.__setitem__(name, value)


def arrayparse(field):
    """parse an array descriptor"""
    arridx = field.find('[')
    if arridx == -1:
        return field, -1
    alen = int(field[arridx + 1:-1])
    fieldname = field[:arridx]
    return fieldname, alen


class UBloxDescriptor:
    """class used to describe the layout of a UBlox message"""

    def __init__(self, name, msg_format, fields=[], count_field=None, format2=None, fields2=None):
        self.name = name
        self.msg_format = msg_format
        self.fields = fields
        self.count_field = count_field
        self.format2 = format2
        self.fields2 = fields2

    def unpack(self, msg):
        """unpack a UBloxMessage, creating the .fields and ._recs attributes in msg"""

        msg._fields = {}

        # unpack main message blocks. A comm
        formats = self.msg_format.split(',')
        buf = msg._buf[6:-2]
        count = 0
        msg._recs = []
        fields = self.fields[:]

        for fmt in formats:
            size1 = struct.calcsize(fmt)
            if size1 > len(buf):
                raise UBloxError("%s INVALID_SIZE1=%u" % (self.name, len(buf)))
            f1 = list(struct.unpack(fmt, buf[:size1]))
            i = 0
            while i < len(f1):
                field = fields.pop(0)
                (fieldname, alen) = arrayparse(field)
                if alen == -1:
                    msg._fields[fieldname] = f1[i]
                    if self.count_field == fieldname:
                        count = int(f1[i])
                    i += 1
                else:
                    msg._fields[fieldname] = [0] * alen
                    for a in range(alen):
                        msg._fields[fieldname][a] = f1[i]
                        i += 1
            buf = buf[size1:]
            if len(buf) == 0:
                break

        if self.count_field == '_remaining':
            count = len(buf) / struct.calcsize(self.format2)

        if count == 0:
            msg._unpacked = True
            if len(buf) != 0:
                raise UBloxError("EXTRA_BYTES=%u" % len(buf))
            return

        size2 = struct.calcsize(self.format2)
        for c in range(count):
            r = UBloxAttrDict()
            if size2 > len(buf):
                raise UBloxError("INVALID_SIZE=%u, " % len(buf))
            f2 = list(struct.unpack(self.format2, buf[:size2]))
            for i in range(len(self.fields2)):
                r[self.fields2[i]] = f2[i]
            buf = buf[size2:]
            msg._recs.append(r)
        if len(buf) != 0:
            raise UBloxError("EXTRA_BYTES=%u" % len(buf))
        msg._unpacked = True

    def pack(self, msg, msg_class=None, msg_id=None):
        """pack a UBloxMessage from the .fields and ._recs attributes in msg"""
        f1 = []
        if msg_class is None:
            msg_class = msg.msg_class()
        if msg_id is None:
            msg_id = msg.msg_id()
        msg._buf = ''

        fields = self.fields[:]
        for f in fields:
            (fieldname, alen) = arrayparse(f)
            if not fieldname in msg._fields:
                break
            if alen == -1:
                f1.append(msg._fields[fieldname])
            else:
                for a in range(alen):
                    f1.append(msg._fields[fieldname][a])
        try:
            # try full length message
            fmt = self.msg_format.replace(',', '')
            msg._buf = struct.pack(fmt, *tuple(f1))
        except Exception as e:
            # try without optional part
            fmt = self.msg_format.split(',')[0]
            msg._buf = struct.pack(fmt, *tuple(f1))

        length = len(msg._buf)
        if msg._recs:
            length += len(msg._recs) * struct.calcsize(self.format2)
        header = struct.pack('<BBBBH', PREAMBLE1, PREAMBLE2, msg_class, msg_id, length)
        msg._buf = header + msg._buf

        for r in msg._recs:
            f2 = []
            for f in self.fields2:
                f2.append(r[f])
            msg._buf += struct.pack(self.format2, *tuple(f2))
        msg._buf += struct.pack('<BB', *msg.checksum(data=msg._buf[2:]))

    def format(self, msg):
        """return a formatted string for a message"""
        if not msg._unpacked:
            self.unpack(msg)
        ret = self.name + ': '
        for f in self.fields:
            (fieldname, alen) = arrayparse(f)
            if not fieldname in msg._fields:
                continue
            v = msg._fields[fieldname]
            if isinstance(v, list):
                ret += '%s=[' % fieldname
                for a in range(alen):
                    ret += '%s, ' % v[a]
                ret = ret[:-2] + '], '
            elif isinstance(v, str):
                ret += '%s="%s", ' % (f, v.rstrip(' \0'))
            else:
                ret += '%s=%s, ' % (f, v)
        for r in msg._recs:
            ret += '[ '
            for f in self.fields2:
                v = r[f]
                ret += '%s=%s, ' % (f, v)
            ret = ret[:-2] + ' ], '
        return ret[:-2]


# list of supported message types.
msg_types = {
    (CLASS_ACK, MSG_ACK_ACK): UBloxDescriptor('ACK_ACK',
                                              '<BB',
                                              ['clsID', 'msgID']),
    (CLASS_ACK, MSG_ACK_NACK): UBloxDescriptor('ACK_NACK',
                                               '<BB',
                                               ['clsID', 'msgID']),
    (CLASS_AID, MSG_AID_ALM): UBloxDescriptor('AID_ALM',  # deprecated, use MGA messages instead
                                              '<II',
                                              ['svid', 'week'],
                                              '_remaining',
                                              'I',
                                              ['dwrd']),
    (CLASS_AID, MSG_AID_AOP): UBloxDescriptor('AID_AOP',  # deprecated, use MGA messages instead
                                              '<BBH , 64B',
                                              ['gnssId', 'svId', 'reserved1', 'data[64]']),
    (CLASS_AID, MSG_AID_EPH): UBloxDescriptor('AID_EPH',  # deprecated, use MGA messages instead
                                              '<II , 8I 8I 8I',
                                              ['svid', 'how', 'sf1d[8]', 'sf2d[8]', 'sf3d[8]']),
    (CLASS_AID, MSG_AID_HUI): UBloxDescriptor('AID_HUI',  # deprecated, use MGA messages instead
                                              '<IffihhhhhhfffffffffI',
                                              ['health', 'utcA0', 'utcA1', 'utcTOW', 'utcWNT', 'utcLS', 'utcWNF',
                                               'utcDN', 'utcLSF', 'utcSpare', 'klobA0', 'klobA1', 'klobA2', 'klobA3',
                                               'klobB0', 'klobB1', 'klobB2', 'klobB3', 'flags']),
    (CLASS_AID, MSG_AID_INI): UBloxDescriptor('AID_INI',  # deprecated, use MGA messages instead
                                              '<iiiIHHIiIIiII',
                                              ['ecefXOrLat', 'ecefYOrLon', 'ecefZOrAlt', 'posAcc', 'tmCfg', 'wnoOrDate',
                                               'towOrTime' 'towNs', 'tAccMs', 'tAccNs', 'clkDOrFreq', 'clkDAccOrFreq',
                                               'flags']),
    (CLASS_CFG, MSG_CFG_ANT): UBloxDescriptor('CFG_ANT',
                                              '<HH',
                                              ['flags', 'pins']),
    (CLASS_CFG, MSG_CFG_CFG): UBloxDescriptor('CFG_CFG',
                                              '<III,B',
                                              ['clearMask', 'saveMask', 'loadMask', 'deviceMask']),
    (CLASS_CFG, MSG_CFG_DAT): UBloxDescriptor('CFG_DAT',
                                              '<H 6s fffffffff',
                                              ['datumNum', 'datumName[6]', 'majA', 'flat', 'dX', 'dY', 'dZ', 'rotX',
                                               'rotY', 'rotZ', 'scale']),
    (CLASS_CFG, MSG_CFG_DOSC): UBloxDescriptor('CFG_DOSC',
                                               '<BB 2B',
                                               ['version', 'numOsc', 'reserved1[2]'],
                                               'numOsc',
                                               'BHIIH 2B iB 3B',
                                               ['oscId', 'reserved2', 'flags', 'freq', 'phaseOffset', 'withTemp',
                                                'withAge', 'timeToTemp', 'reserved3[2]', 'gainVco', 'gainUncertainty',
                                                'reserved4[3]']),
    (CLASS_CFG, MSG_CFG_DYNSEED): UBloxDescriptor('CFG_DYNSEED',
                                                  '<B 3B II',
                                                  ['version', 'reserved1', 'seedHi', 'seedLo']),
    (CLASS_CFG, MSG_CFG_ESRC): UBloxDescriptor('CFG_ESRC',
                                               '<BB 2B',
                                               ['version', 'numSources', 'reserved1'],
                                               'numSources',
                                               'BBHI 4B IHHiII',
                                               ['extInt', 'sourceType', 'flags', 'freq', 'reserved2', 'withTemp',
                                                'withAge', 'timeToTemp', 'maxDevLifeTime', 'offset',
                                                'offsetUncertainty', 'jitter']),
    (CLASS_CFG, MSG_CFG_FIXSEED): UBloxDescriptor('CFG_FIXSEED',
                                                  '<BB 2B II',
                                                  ['version', 'length', 'seedHi', 'seedLo'],
                                                  'length',
                                                  'BB',
                                                  ['classID', 'msgId']),
    (CLASS_CFG, MSG_CFG_GEOFENCE): UBloxDescriptor('CFG_GEOFENCE',
                                                   '<BBBBBBBB',
                                                   ['version', 'numFences', 'confLvl', 'reserved1', 'pioEnabled',
                                                    'pinPolarity', 'pin', 'reserved2'],
                                                   'numFences',
                                                   'iiI',
                                                   ['lat', 'lon', 'radius']),
    (CLASS_CFG, MSG_CFG_GNSS): UBloxDescriptor('CFG_GNSS',
                                               '<BBBB',
                                               ['msgVer', 'numTrkChHw', 'numTrkChUse', 'numConfigBlocks'],
                                               'numConfigBlocks',
                                               'BBBBI',
                                               ['gnssId', 'resTrkCh', 'macTrkCh', 'reserved1', 'flags']),
    (CLASS_CFG, MSG_CFG_INF): UBloxDescriptor('CFG_INF',
                                              '<',
                                              [],
                                              '_remaining',
                                              'B 3B 6B',
                                              ['protocolID', 'reserved1', 'infMsgMask[6]']),
    (CLASS_CFG, MSG_CFG_ITFM): UBloxDescriptor('CFG_ITFM',
                                               '<II',
                                               ['config', 'config2']),
    (CLASS_CFG, MSG_CFG_LOGFILTER): UBloxDescriptor('CFG_LOGFILTER',
                                                    '<BBHHHI',
                                                    ['version', 'flags', 'minInterval', 'timeThreshold',
                                                     'speedThreshold', 'positionThreshold']),
    (CLASS_CFG, MSG_CFG_MSG): UBloxDescriptor('CFG_MSG',
                                              '<BB 6B',
                                              ['msgClass', 'msgID', 'rate[6]']),
    (CLASS_CFG, MSG_CFG_NMEA): UBloxDescriptor('CFG_NMEA',
                                               '<BBBIBBBB 2s 6B',
                                               ['nmeaVersion', 'numSV', 'flags', 'gnssToFilter', 'svNumbering',
                                                'mainTalkerId', 'gsvTalkerIf', 'version', 'bdsTalkerId', 'reserved1']),
    (CLASS_CFG, MSG_CFG_ODO): UBloxDescriptor('CFG_ODO',  # Not supported on FTS variants
                                              '<B 3B BB 6B BB 2B BB 2B',
                                              ['version', 'reserved1' 'flags', 'odoCfg', 'reserved2', 'cogMaxSpeed',
                                               'codMaxPosAcc', 'reserved3', 'velLpGain', 'cogLpGain', 'reserved4']),
    (CLASS_CFG, MSG_CFG_PM2): UBloxDescriptor('CFG_PM2',  # Protocol version 18 to 22
                                              '<BBBBIIIIHH 20B I',
                                              ['version', 'reserved1', 'maxStartupStateDur', 'reserved2', 'flags',
                                               'updatePeriod', 'searchPeriod', 'gridOffset', 'onTime', 'minAcqTime',
                                               'reserved3', 'extintInactivityMs']),
    (CLASS_CFG, MSG_CFG_PMS): UBloxDescriptor('CFG_PMS',  # Protocol version 18 to 22
                                              '<BBHH 2B',
                                              ['version', 'powerSetupValue', 'period', 'onTime', 'reserved1']),
    (CLASS_CFG, MSG_CFG_USB): UBloxDescriptor('CFG_USB',
                                              '<HHHHHH32s32s32s',
                                              ['vendorID', 'productID', 'reserved1', 'reserved2', 'powerConsumption',
                                               'flags', 'vendorString', 'productString', 'serialNumber']),
    (CLASS_CFG, MSG_CFG_PRT): UBloxDescriptor('CFG_PRT',
                                              '<BBHIIHHHH',
                                              ['portID', 'reserved1', 'txReady', 'mode', 'baudRate', 'inProtoMask',
                                               'outProtoMask', 'flags', 'reserved2']),
    (CLASS_CFG, MSG_CFG_RATE): UBloxDescriptor('CFG_RATE',  # Not supported on FTS variants
                                               '<HHH',
                                               ['measRate', 'navRate', 'timeRef']),
    (CLASS_CFG, MSG_CFG_RINV): UBloxDescriptor('CFG_RINV',
                                               '<B, B',
                                               ['flags', 'data']),
    (CLASS_CFG, MSG_CFG_RST): UBloxDescriptor('CFG_RST',
                                              '<HBB',
                                              ['navBbrMask ', 'resetMode', 'reserved1']),
    (CLASS_CFG, MSG_CFG_RXM): UBloxDescriptor('CFG_RXM',
                                              '<BB',
                                              ['reserved1', 'lpMode']),
    (CLASS_CFG, MSG_CFG_SBAS): UBloxDescriptor('CFG_SBAS',
                                               '<BBBBI',
                                               ['mode', 'usage', 'maxSBAS', 'scanmode2', 'scanmode1']),
    (CLASS_CFG, MSG_CFG_SMGR): UBloxDescriptor('CFG_SMGR',  # Only supported in Time and Frequency products
                                               '<BBHH 2B HHHHI',
                                               ['version', 'minGNSSFix', 'maxFreqChangeRate', 'maxPhaseCorrRate',
                                                'reserved1', 'freqTolerance', 'timeTolerance', 'messageCfg',
                                                'maxSlewRate', 'flags']),
    (CLASS_CFG, MSG_CFG_TMODE2): UBloxDescriptor('CFG_TMODE2',  # Only supported in Time and Frequency products
                                                 '<BBHiiiIII',
                                                 ['timeMode', 'reserved1', 'flags', 'ecefXOrLat', 'ecefYOrLon',
                                                  'ecefZOrAlt', 'fixedPosAcc', 'svinMinDur', 'svinAccLimit']),
    (CLASS_CFG, MSG_CFG_TP5): UBloxDescriptor('CFG_TP5',  # Protocol version 16 to 22
                                              '<BB 2B hhIIIIiI',
                                              ['tpIdx', 'version', 'reserved1', 'antCableDelay', 'rfGroupDelay',
                                               'freqPeriod', 'freqPeriodLock', 'pulseLenRatio', 'pulseLenRatioLock',
                                               'userConfigDelay', 'flags']),
    (CLASS_LOG, MSG_LOG_FINDTIME): UBloxDescriptor('LOG_FINDTIME',
                                                   '<BBHI',
                                                   ['version', 'type', 'reserved1', 'entryNumber']),
    (CLASS_LOG, MSG_LOG_INFO): UBloxDescriptor('LOG_INFO',
                                               '<B 3B I 8B IIIHBBBBBBHBBBBBBB 3B',
                                               ['version', 'reserved1', 'filestoreCapacity', 'reserved2',
                                                'currentMaxLogSize', 'currentLogSize', 'entryCount', 'oldestYear',
                                                'oldestMonth', 'oldestDay', 'oldestHour', 'oldestMinute',
                                                'oldestSecond', 'reserved3', 'newestYear', 'newestMonth', 'newestDay',
                                                'newestHour', 'newestMinute', 'newestSecond', 'reserved4', 'status',
                                                'reserved5']),
    (CLASS_LOG, MSG_LOG_RETRIEVEPOSEXTRA): UBloxDescriptor('LOG_RETRIEVEPOSEXTRA',
                                                           '<IBBHBBBBB 3B I 12B',
                                                           ['entryIndex', 'version', 'reserved1', 'year', 'month',
                                                            'day', 'hour', 'minute', 'second', 'reserved2', 'distance',
                                                            'reserved3']),
    (CLASS_LOG, MSG_LOG_RETRIEVEPOS): UBloxDescriptor('LOG_RETRIEVEPOS',
                                                      '<IiiiIIIBBHBBBBBBBB',
                                                      ['entryIndex', 'lon', 'lat', 'hMSL', 'hAcc', 'gSpeed', 'heading',
                                                       'version', 'fixType', 'year', 'month', 'day', 'hour', 'minute',
                                                       'second', 'reserved1', 'numSV', 'reserved2']),
    (CLASS_LOG, MSG_LOG_RETRIEVESTRING): UBloxDescriptor('LOG_RETIEVESTRING',
                                                         '<IBBHBBBBBBH',
                                                         ['entryIndex', 'version', 'reserved1', 'year', 'month', 'hour',
                                                          'minute', 'second', 'reserved2', 'byteCount'],
                                                         'byteCount',
                                                         'B',
                                                         ['bytes']),
    (CLASS_MGA, MSG_MGA_ACK): UBloxDescriptor('MGA_ACK',
                                              '<BBBB 4B',
                                              ['type', 'version', 'infoCode', 'msgId', 'msgPayloadStart']),
    (CLASS_MGA, MSG_MGA_DBD): UBloxDescriptor('MGA_DBD',
                                              '<12B, B',
                                              ['reserved1', 'data']),
    (CLASS_MGA, MSG_MGA_FLASH): UBloxDescriptor('MGA_FLASH',
                                                '<BBBBH',
                                                ['typr', 'version', 'ack', 'reserved1', 'sequence']),
    (CLASS_MON, MSG_MON_GNSS): UBloxDescriptor('MON_GNSS',
                                               '<BBBBB 3B',
                                               ['version', 'supported', 'default', 'enabled', 'simultaneous',
                                                'reserved1']),
    (CLASS_MON, MSG_MON_HW2): UBloxDescriptor('MON_HW2',
                                              '<bBbBB 3B I 8B I 4B',
                                              ['ofsI', 'magI', 'ofsQ', 'magQ', 'cfgSource', 'reserved1', 'lowLevCfg',
                                               'reserved2', 'postStatus', 'reserved3']),
    (CLASS_MON, MSG_MON_HW): UBloxDescriptor('MON_HW',
                                             '<IIIIHHBBBBI 17B B 2B III',
                                             ['pinSel', 'pinBank', 'pinDir', 'pinVal', 'noisePerMs', 'agcCnt',
                                              'aStatus', 'aPower', 'flags', 'reseverd1', 'usedMask', 'VP', 'jamId',
                                              'reserved2', 'pinIrq', 'pullH', 'pullL']),
    (CLASS_MON, MSG_MON_IO): UBloxDescriptor('MON_IO',  # TODO check message format
                                             '<, IIHHHHBB 2B',
                                             ['rxBytes', 'txBytes', 'parityErrs', 'framingErrs', 'overrunErrs',
                                              'breakCond', 'rxBusy', 'txBusy', 'reserved1']),
    (CLASS_MON, MSG_MON_MSGPP): UBloxDescriptor('MON_MSGPP',
                                                '<8H 8H 8H 8H 8H 8H 6I',
                                                ['msg1', 'msg2', 'msg3', 'msg4', 'msg5', 'msg6', 'skipped']),
    (CLASS_MON, MSG_MON_PATCH): UBloxDescriptor('MON_PATCH',
                                                '<HH',
                                                ['version', 'nEntries'],
                                                'nEntries',
                                                'IIII',
                                                ['patchInfo', 'comparatorNumber', 'patchAddress', 'patchData']),
    (CLASS_MON, MSG_MON_RXBUF): UBloxDescriptor('MON_RXBUF',
                                                '<6H 6B 6B',
                                                ['pending', 'usuage', 'peakUsuage']),
    (CLASS_MON, MSG_MON_RXR): UBloxDescriptor('MON_RXR',
                                              '<B',
                                              ['flags']),
    (CLASS_MON, MSG_MON_SMGR): UBloxDescriptor('MON_SMGR',  # Only supported with Time & Frequency products
                                               '<B 3B I HHBBBB',
                                               ['version', 'reserved1', 'iTOW', 'intOsc', 'extOsc', 'discSrc', 'gnss',
                                                'extInt0', 'extInt1']),
    (CLASS_MON, MSG_MON_TXBUF): UBloxDescriptor('MON_TXBUF',
                                                '<6H 6B 6B BBBB',
                                                ['pending', 'usuage', 'peakUsuage', 'tUsuage', 'tPeakusuage', 'errors',
                                                 'reserved1']),
    (CLASS_MON, MSG_MON_VER): UBloxDescriptor('MON_VER',
                                              '<30s 10s, 30s',
                                              ['swVersion', 'hwVersion', 'extension']),
    (CLASS_NAV, MSG_NAV_AOPSTATUS): UBloxDescriptor('NAV_AOPSTATUS',
                                                    '<IBB 10B',
                                                    ['iTOW', 'aopCfg', 'status', 'reserved1']),
    (CLASS_NAV, MSG_NAV_CLOCK): UBloxDescriptor('NAV_CLOCK',
                                                '<IiiII',
                                                ['iTOW', 'clkB', 'clkD', 'tAcc', 'fAcc']),
    (CLASS_NAV, MSG_NAV_EOE): UBloxDescriptor('NAV_EOE',  # Supported in versions 18 to 22
                                              '<I',
                                              ['iTOW']),
    (CLASS_NAV, MSG_NAV_GEOFENCE): UBloxDescriptor('NAV_GEOFENCE',
                                                   '<IBBBB',
                                                   ['iTOW', 'version', 'status', 'numFences', 'comState'],
                                                   'numFence',
                                                   'BB',
                                                   ['state', 'reserved1']),
    (CLASS_NAV, MSG_NAV_ODO): UBloxDescriptor('NAV_ODO',
                                              '<B 3B IIII',
                                              ['version', 'reserved1', 'iTOW', 'ditance', 'totalDistance',
                                               'distanceStd']),
    (CLASS_NAV, MSG_NAV_ORB): UBloxDescriptor('NAV_ORB',
                                              '<IBBH',
                                              ['iTOW', 'version', 'numSv', 'reserved1'],
                                              'numSv',
                                              'BBBBBB',
                                              ['gnssID', 'svId', 'svFlag', 'eph', 'alm', 'otherOrb']),
    (CLASS_NAV, MSG_NAV_POSLLH): UBloxDescriptor('NAV_POSLLH',
                                                 '<IiiiiII',
                                                 ['iTOW', 'Longitude', 'Latitude', 'height', 'hMSL', 'hAcc', 'vAcc']),
    (CLASS_NAV, MSG_NAV_PVT): UBloxDescriptor('NAV_PVT',
                                              '<IHBBBBBBIiBBBBiiiiIIiiiiiIIH 6B i 4B',
                                              ['iTOW', 'year', 'month', 'day', 'hour', 'min', 'sec', 'valid', 'tAcc',
                                               'nano', 'fixType', 'flags', 'flags2', 'numSv', 'lon', 'lat', 'height',
                                               'hMSL', 'hAcc', 'velN', 'velE', 'velD', 'gSpeed', 'headMot', 'sAcc',
                                               'headAcc', 'pDOP', 'reserved1', 'headVeh', 'reserved2']),
    (CLASS_NAV, MSG_NAV_SAT): UBloxDescriptor('NAV_SAT',
                                              '<IBBH',
                                              ['iTOW', 'version', 'numSvs', 'reserved1'],
                                              'numSvs',
                                              'BBBbhhI',
                                              ['gnssId', 'svId', 'cno', 'elev', 'azim', 'prRes', 'flags']),
    (CLASS_NAV, MSG_NAV_VELNED): UBloxDescriptor('NAV_VELNED',
                                                 '<IiiiIIiII',
                                                 ['iTOW', 'velN', 'velE', 'velD', 'speed', 'gSpeed', 'heading',
                                                  'sAcc', 'cAcc']),
    (CLASS_NAV, MSG_NAV_DOP): UBloxDescriptor('NAV_DOP',
                                              '<IHHHHHHH',
                                              ['iTOW', 'gDOP', 'pDOP', 'tDOP', 'vDOP', 'hDOP', 'nDOP', 'eDOP']),
    (CLASS_NAV, MSG_NAV_STATUS): UBloxDescriptor('NAV_STATUS',
                                                 '<IBBBBII',
                                                 ['iTOW', 'gpsFix', 'flags', 'fixStat', 'flags2', 'ttff', 'msss']),
    (CLASS_NAV, MSG_NAV_SOL): UBloxDescriptor('NAV_SOL',
                                              '<IihBBiiiIiiiIHBBI',
                                              ['iTOW', 'fTOW', 'week', 'gpsFix', 'flags', 'ecefX', 'ecefY', 'ecefZ',
                                               'pAcc', 'ecefVX', 'ecefVY', 'ecefVZ', 'sAcc', 'pDOP', 'reserved1',
                                               'numSV', 'reserved2']),
    (CLASS_NAV, MSG_NAV_POSUTM): UBloxDescriptor('NAV_POSUTM',
                                                 '<Iiiibb',
                                                 ['iTOW', 'East', 'North', 'Alt', 'Zone', 'Hem']),
    (CLASS_NAV, MSG_NAV_SBAS): UBloxDescriptor('NAV_SBAS',
                                               '<IBBbBBBBB',
                                               ['iTOW', 'geo', 'mode', 'sys', 'service', 'cnt', 'reserved01',
                                                'reserved02', 'reserved03'],
                                               'cnt',
                                               'BBBBBBhHh',
                                               ['svid', 'flags', 'udre', 'svSys', 'svService', 'reserved1',
                                                'prc', 'reserved2', 'ic']),
    (CLASS_NAV, MSG_NAV_POSECEF): UBloxDescriptor('NAV_POSECEF',
                                                  '<IiiiI',
                                                  ['iTOW', 'ecefX', 'ecefY', 'ecefZ', 'pAcc']),
    (CLASS_NAV, MSG_NAV_VELECEF): UBloxDescriptor('NAV_VELECEF',
                                                  '<IiiiI',
                                                  ['iTOW', 'ecefVX', 'ecefVY', 'ecefVZ', 'sAcc']),
    (CLASS_NAV, MSG_NAV_TIMEBDS): UBloxDescriptor('NAV_TIMEBDS',
                                                  '<IIihbBI',
                                                  ['iTOW', 'SOW', 'fSOW', 'week', 'leapS', 'valid', 'tAcc']),
    (CLASS_NAV, MSG_NAV_TIMEGAL): UBloxDescriptor('NAV_TIMEGAL',
                                                  '<IIihbBI',
                                                  ['iTOW', 'galTow', 'fGalTow', 'galWno', 'leapS', 'valid', 'tAcc']),
    (CLASS_NAV, MSG_NAV_TIMEGLO): UBloxDescriptor('NAV_TIMEGLO',
                                                  '<IIiHBBI',
                                                  ['iTOW', 'TOD', 'fTOD', 'Nt', 'N4', 'valid', 'tAcc']),
    (CLASS_NAV, MSG_NAV_TIMEGPS): UBloxDescriptor('NAV_TIMEGPS',
                                                  '<IihbBI',
                                                  ['iTOW', 'fTOW', 'week', 'leapS', 'valid', 'tAcc']),
    (CLASS_NAV, MSG_NAV_TIMELS): UBloxDescriptor('NAV_TIMELS',
                                                 '<IB 3B BbBbiBB 3B B',
                                                 ['iTOW', 'version', 'reserved1', 'srcOfCurrLs', 'currLs',
                                                  'srcOfLsChange', 'lsChange', 'timeToLsEvent', 'dateOfLsGpsWn',
                                                  'dateofLsGpsDn', 'reserved2', 'valid']),
    (CLASS_NAV, MSG_NAV_TIMEUTC): UBloxDescriptor('NAV_TIMEUTC',
                                                  '<IIiHBBBBBB',
                                                  ['iTOW', 'tAcc', 'nano', 'year', 'month', 'day', 'hour', 'min', 'sec',
                                                   'valid']),
    (CLASS_NAV, MSG_NAV_CLOCK): UBloxDescriptor('NAV_CLOCK',
                                                '<IiiII',
                                                ['iTOW', 'clkB', 'clkD', 'tAcc', 'fAcc']),
    (CLASS_NAV, MSG_NAV_DGPS): UBloxDescriptor('NAV_DGPS',
                                               '<IihhBBH',
                                               ['iTOW', 'age', 'baseId', 'baseHealth', 'numCh', 'status', 'reserved1'],
                                               'numCh',
                                               '<BBHff',
                                               ['svid', 'flags', 'ageC', 'prc', 'prrc']),
    (CLASS_NAV, MSG_NAV_SVINFO): UBloxDescriptor('NAV_SVINFO',
                                                 '<IBBH',
                                                 ['iTOW', 'numCh', 'globalFlags', 'reserved2'],
                                                 'numCh',
                                                 '<BBBBBbhi',
                                                 ['chn', 'svid', 'flags', 'quality', 'cno', 'elev', 'azim', 'prRes']),
    (CLASS_RXM, MSG_RXM_IMES): UBloxDescriptor('RXM_IMES',  # Supported in versions 18 to 22
                                               '<BBH',
                                               ['numTx', 'version', 'reserved1'],
                                               'numTx',
                                               'BB 3B BHiIIIiiIII',
                                               ['reserved2', 'tcId', 'reserved3', 'cno', 'reserved4', 'doppler',
                                                'position1_1', 'position1_2', 'position2_1', 'lat', 'lon',
                                                'shortIdFrame', 'mediumIdLSB', 'mediumId_2']),
    (CLASS_RXM, MSG_RXM_MEASX): UBloxDescriptor('RXM_MEAS',  # Supported in versions 18 to 22
                                                '<B 3B IIIIIHHHHHBB 8B',
                                                ['version', 'reserved1', 'gpsTOW', 'gloTOW', 'bdsTOW', 'reserved2',
                                                 'qzssTOW', 'gpsTOWacc', 'gloTOWacc', 'bdsTOWacc', 'reserved3',
                                                 'qzssTOWacc', 'numSV', 'flags', 'reserved4'],
                                                'numSV',
                                                'BBBBiiHHIBBH',
                                                ['gnssId', 'svId', 'cNo', 'mpathIndic', 'dopplerMS', 'dopplerHz',
                                                 'wholeChips', 'fracChips', 'codePhase', 'pseuRangeRMSErr',
                                                 'reserved5']),
    (CLASS_RXM, MSG_RXM_RLM): UBloxDescriptor('RXM_RLM',  # Supported in versions 18 to 22
                                              '<BBBB 8B B',
                                              ['version', 'type', 'svId', 'reserved1', 'beacon', 'message'],
                                              '_remaining',
                                              'B',
                                              ['params']),  # Have included reserved2 in with params for longer version,
                                                            #  won't check if message is 16 or 28 bytes
    (CLASS_RXM, MSG_RXM_SVSI): UBloxDescriptor('RXM_SVSI',
                                               '<IhBB',
                                               ['iTOW', 'week', 'numVis', 'numSV'],
                                               'numSV',
                                               '<BBhbB',
                                               ['svid', 'svFlag', 'azim', 'elev', 'age']),
    (CLASS_RXM, MSG_RXM_EPH): UBloxDescriptor('RXM_EPH',
                                              '<II , 8I 8I 8I',
                                              ['svid', 'how',
                                               'sf1d[8]', 'sf2d[8]', 'sf3d[8]']),
    (CLASS_RXM, MSG_RXM_RAW): UBloxDescriptor('RXM_RAW',
                                              '<ihBB',
                                              ['iTOW', 'week', 'numSV', 'reserved1'],
                                              'numSV',
                                              '<ddfBbbB',
                                              ['cpMes', 'prMes', 'doMes', 'sv', 'mesQI', 'cno', 'lli']),
    (CLASS_RXM, MSG_RXM_RAWX): UBloxDescriptor('RXM_RAWX',  # Supported in versions 18 to 22
                                               '<dHbBBBH',
                                               ['rcvTow', 'week', 'leapS', 'numMeas', 'recStat', 'version',
                                                'reserved1'],
                                               'numMeas',
                                               'ddfBBBBHBBBBBB',
                                               ['prMes', 'cpMes', 'doMes', 'gnssId', 'svId', 'reserved2', 'freqId',
                                                'locktime', 'cno', 'prStdev', 'spDtdev', 'doStdev', 'trkStat',
                                                'reserved3']),
    (CLASS_RXM, MSG_RXM_SFRB): UBloxDescriptor('RXM_SFRB',  # Supported in versions 18 to 22
                                               '<BBBBBBBB',
                                               ['gnssId', 'svId', 'reserved','freqId', 'numWords', 'chn', 'version',
                                                'reserved2'],
                                               'numWords',
                                               'I',
                                               ['dwrd']),
    (CLASS_RXM, MSG_RXM_ALM): UBloxDescriptor('RXM_ALM',
                                              '<II , 8I',
                                              ['svid', 'week', 'dwrd[8]']),
    (CLASS_CFG, MSG_CFG_NAV5): UBloxDescriptor('CFG_NAV5',
                                               '<HBBiIbBHHHHBBBB 2B HB 5B',
                                               ['mask', 'dynModel', 'fixMode', 'fixedAlt', 'fixedAltVar', 'minElev',
                                                'drLimit', 'pDop', 'tDop', 'pAcc', 'tAcc', 'staticHoldThresh',
                                                'dgpsTimeOut', 'cnoThreshNumSVs', 'cnoThresh', 'reserved1',
                                                'staticHoldMaxDist', 'utcStandard', 'reserved2']),
    (CLASS_CFG, MSG_CFG_NAVX5): UBloxDescriptor('CFG_NAVX5',  # CFG_NAVX5 Valid for Protocol Versions 18 to 22
                                                '<HHI 2B BBBBB 2B BHBB 2B 2B BB 2B H 4B 3B B',
                                                ['version', 'mask1', 'mask2', 'reserved1', 'minSVs', 'maxSVs', 'minCNO',
                                                 'reserved2', 'iniFix3D', 'reserved3', 'ackAiding', 'wknRollover',
                                                 'sigAttenCompMode', 'reserved4', 'reserved5', 'reserved6', 'usePPP',
                                                 'aopCfg', 'reserved7', 'aopOrbMaxErr', 'reserved8', 'reserved9',
                                                 'useAdr']),
    (CLASS_MON, MSG_MON_HW): UBloxDescriptor('MON_HW',
                                             '<IIIIHHBBBBIB25BHIII',
                                             ['pinSel', 'pinBank', 'pinDir', 'pinVal', 'noisePerMS', 'agcCnt',
                                              'aStatus',
                                              'aPower', 'flags', 'reserved1', 'usedMask',
                                              'VP[25]',
                                              'jamInd', 'reserved3', 'pinInq',
                                              'pullH', 'pullL']),
    (CLASS_MON, MSG_MON_SCHD): UBloxDescriptor('MON_SCHD',
                                               '<IIIIHHHBB',
                                               ['tskRun', 'tskSchd', 'tskOvrr', 'tskReg', 'stack',
                                                'stackSize', 'CPUIdle', 'flySly', 'ptlSly']),
    (CLASS_MON, MSG_MON_VER): UBloxDescriptor('MON_VER',
                                              '<30s10s,30s',
                                              ['swVersion', 'hwVersion', 'romVersion'],
                                              '_remaining',
                                              '30s',
                                              ['extension']),
    (CLASS_SEC, MSG_SEC_SIGN): UBloxDescriptor('SEC_SIGN',  # Supported in versions 18 to 22
                                               '<B 3B BBH 32B',
                                               ['version', 'reserved1', 'classID', 'messageID', 'checksum', 'hash']),
    (CLASS_SEC, MSG_SEC_UNIQID): UBloxDescriptor('SEC_UNIQID',
                                                 '<B 3B 5B',
                                                 ['version', 'reserved1', 'uniqueId']),
    (CLASS_TIM, MSG_TIM_TP): UBloxDescriptor('TIM_TP',
                                             '<IIiHBB',
                                             ['towMS', 'towSubMS', 'qErr', 'week', 'flags', 'reserved1']),
    (CLASS_TIM, MSG_TIM_TM2): UBloxDescriptor('TIM_TM2',
                                              '<BBHHHIIIII',
                                              ['ch', 'flags', 'count', 'wnR', 'wnF', 'towMsR', 'towSubMsR',
                                               'towMsF', 'towSubMsF', 'accEst']),
    (CLASS_TIM, MSG_TIM_SVIN): UBloxDescriptor('TIM_SVIN',
                                               '<IiiiIIBBH',
                                               ['dur', 'meanX', 'meanY', 'meanZ', 'meanV',
                                                'obs', 'valid', 'active', 'reserved1'])
}


class UBloxMessage:
    """UBlox message class - holds a UBX binary message"""

    def __init__(self):
        self._buf = ""
        self._fields = {}
        self._recs = []
        self._unpacked = False
        self.debug_level = 0

    def __str__(self):
        """format a message as a string"""
        if not self.valid():
            return 'UBloxMessage(INVALID)'
        type = self.msg_type()
        if type in msg_types:
            return msg_types[type].format(self)
        return 'UBloxMessage(UNKNOWN %s, %u)' % (str(type), self.msg_length())

    def __getattr__(self, name):
        """allow access to message fields"""
        try:
            return self._fields[name]
        except KeyError:
            if name == 'recs':
                return self._recs
            raise AttributeError(name)

    def __setattr__(self, name, value):
        """allow access to message fields"""
        if name.startswith('_'):
            self.__dict__[name] = value
        else:
            self._fields[name] = value

    def have_field(self, name):
        """return True if a message contains the given field"""
        return name in self._fields

    def debug(self, level, msg):
        """write a debug message"""
        if self.debug_level >= level:
            print(msg)

    def unpack(self):
        """unpack a message"""
        if not self.valid():
            raise UBloxError('INVALID MESSAGE')
        type = self.msg_type()
        if not type in msg_types:
            raise UBloxError('Unknown message %s length=%u' % (str(type), len(self._buf)))
        msg_types[type].unpack(self)

    def pack(self):
        """pack a message"""
        if not self.valid():
            raise UbloxError('INVALID MESSAGE')
        type = self.msg_type()
        if not type in msg_types:
            raise UBloxError('Unknown message %s' % str(type))
        msg_types[type].pack(self)

    def name(self):
        """return the short string name for a message"""
        if not self.valid():
            raise UbloxError('INVALID MESSAGE')
        type = self.msg_type()
        if not type in msg_types:
            raise UBloxError('Unknown message %s length=%u' % (str(type), len(self._buf)))
        return msg_types[type].name

    def msg_class(self):
        """return the message class"""
        return ord(self._buf[2])

    def msg_id(self):
        """return the message id within the class"""
        return ord(self._buf[3])

    def msg_type(self):
        """return the message type tuple (class, id)"""
        return self.msg_class(), self.msg_id()

    def msg_length(self):
        """return the payload length"""
        (payload_length,) = struct.unpack('<H', self._buf[4:6])
        return payload_length

    def valid_so_far(self):
        """check if the message is valid so far"""
        if len(self._buf) > 0 and ord(self._buf[0]) != PREAMBLE1:
            return False
        if len(self._buf) > 1 and ord(self._buf[1]) != PREAMBLE2:
            self.debug(1, "bad pre2")
            return False
        if self.needed_bytes() == 0 and not self.valid():
            if len(self._buf) > 8:
                self.debug(1, "bad checksum len=%u needed=%u" % (len(self._buf), self.needed_bytes()))
            else:
                self.debug(1, "bad len len=%u needed=%u" % (len(self._buf), self.needed_bytes()))
            return False
        return True

    def add(self, bytes):
        """add some bytes to a message"""
        self._buf += bytes
        while not self.valid_so_far() and len(self._buf) > 0:
            '''handle corrupted streams'''
            self._buf = self._buf[1:]
        if self.needed_bytes() < 0:
            self._buf = ""

    def checksum(self, data=None):
        """return a checksum tuple for a message"""
        if data is None:
            data = self._buf[2:-2]
        cs = 0
        ck_a = 0
        ck_b = 0
        for i in data:
            ck_a = (ck_a + ord(i)) & 0xFF
            ck_b = (ck_b + ck_a) & 0xFF
        return ck_a, ck_b

    def valid_checksum(self):
        """check if the checksum is OK"""
        (ck_a, ck_b) = self.checksum()
        d = self._buf[2:-2]
        (ck_a2, ck_b2) = struct.unpack('<BB', self._buf[-2:])
        return ck_a == ck_a2 and ck_b == ck_b2

    def needed_bytes(self):
        """return number of bytes still needed"""
        if len(self._buf) < 6:
            return 8 - len(self._buf)
        return self.msg_length() + 8 - len(self._buf)

    def valid(self):
        """check if a message is valid"""
        return len(self._buf) >= 8 and self.needed_bytes() == 0 and self.valid_checksum()


class UBlox:
    """main UBlox control class.

    port can be a file (for reading only) or a serial device
    """

    def __init__(self, port, baudrate=115200, timeout=0):

        self.serial_device = port
        self.baudrate = baudrate
        self.use_sendrecv = False
        self.read_only = False
        self.debug_level = 0

        if self.serial_device.startswith("tcp:"):
            import socket
            a = self.serial_device.split(':')
            destination_addr = (a[1], int(a[2]))
            self.dev = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.dev.connect(destination_addr)
            self.dev.setblocking(1)
            self.dev.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.use_sendrecv = True
        elif os.path.isfile(self.serial_device):
            self.read_only = True
            self.dev = open(self.serial_device, mode='rb')
        else:
            import serial
            self.dev = serial.Serial(self.serial_device, baudrate=self.baudrate,
                                     dsrdtr=False, rtscts=False, xonxoff=False, timeout=timeout)
        self.logfile = None
        self.log = None
        self.preferred_dynamic_model = None
        self.preferred_usePPP = None
        self.preferred_dgps_timeout = None

    def close(self):
        """close the device"""
        self.dev.close()
        self.dev = None

    def set_debug(self, debug_level):
        """set debug level"""
        self.debug_level = debug_level

    def debug(self, level, msg):
        """write a debug message"""
        if self.debug_level >= level:
            print(msg)

    def set_logfile(self, logfile, append=False):
        """setup logging to a file"""
        if self.log is not None:
            self.log.close()
            self.log = None
        self.logfile = logfile
        if self.logfile is not None:
            if append:
                mode = 'ab'
            else:
                mode = 'wb'
            self.log = open(self.logfile, mode=mode)

    def set_preferred_dynamic_model(self, model):
        """set the preferred dynamic model for receiver"""
        self.preferred_dynamic_model = model
        if model is not None:
            self.configure_poll(CLASS_CFG, MSG_CFG_NAV5)

    def set_preferred_dgps_timeout(self, timeout):
        """set the preferred DGPS timeout for receiver"""
        self.preferred_dgps_timeout = timeout
        if timeout is not None:
            self.configure_poll(CLASS_CFG, MSG_CFG_NAV5)

    def set_preferred_usePPP(self, usePPP):
        """set the preferred usePPP setting for the receiver"""
        if usePPP is None:
            self.preferred_usePPP = None
            return
        self.preferred_usePPP = int(usePPP)
        self.configure_poll(CLASS_CFG, MSG_CFG_NAVX5)

    def nmea_checksum(self, msg):
        d = msg[1:]
        cs = 0
        for i in d:
            cs ^= ord(i)
        return cs

    def write(self, buf):
        """write some bytes"""
        if not self.read_only:
            if self.use_sendrecv:
                return self.dev.send(buf)
            return self.dev.write(buf)

    def read(self, n):
        """read some bytes"""
        if self.use_sendrecv:
            import socket
            try:
                return self.dev.recv(n)
            except socket.error as e:
                return ''
        return self.dev.read(n)

    def send_nmea(self, msg):
        if not self.read_only:
            s = msg + "*%02X" % self.nmea_checksum(msg)
            self.write(s)

    def set_binary(self):
        """put a UBlox into binary mode using a NMEA string"""
        if not self.read_only:
            self.send_nmea("$PUBX,41,1,0007,0001,%u,0" % self.baudrate)

    def seek_percent(self, pct):
        """seek to the given percentage of a file"""
        self.dev.seek(0, 2)
        filesize = self.dev.tell()
        self.dev.seek(pct * 0.01 * filesize)

    def special_handling(self, msg):
        """handle automatic configuration changes"""
        if msg.name() == 'CFG_NAV5':
            msg.unpack()
            sendit = False
            pollit = False
            if self.preferred_dynamic_model is not None and msg.dynModel != self.preferred_dynamic_model:
                msg.dynModel = self.preferred_dynamic_model
                sendit = True
                pollit = True
            if self.preferred_dgps_timeout is not None and msg.dgpsTimeOut != self.preferred_dgps_timeout:
                msg.dgpsTimeOut = self.preferred_dgps_timeout
                self.debug(2, "Setting dgpsTimeOut=%u" % msg.dgpsTimeOut)
                sendit = True
                # we don't re-poll for this one, as some receivers refuse to set it
            if sendit:
                msg.pack()
                self.send(msg)
                if pollit:
                    self.configure_poll(CLASS_CFG, MSG_CFG_NAV5)
        if msg.name() == 'CFG_NAVX5' and self.preferred_usePPP is not None:
            msg.unpack()
            if msg.usePPP != self.preferred_usePPP:
                msg.usePPP = self.preferred_usePPP
                msg.mask = 1 << 13
                msg.pack()
                self.send(msg)
                self.configure_poll(CLASS_CFG, MSG_CFG_NAVX5)

    def receive_message(self, ignore_eof=False):
        """blocking receive of one ublox message"""
        msg = UBloxMessage()
        while True:
            n = msg.needed_bytes()
            b = self.read(n)
            if not b:
                if ignore_eof:
                    time.sleep(0.01)
                    continue
                return None
            msg.add(b)
            if self.log is not None:
                self.log.write(b)
                self.log.flush()
            if msg.valid():
                self.special_handling(msg)
                return msg

    def receive_message_noerror(self, ignore_eof=False):
        """blocking receive of one ublox message, ignoring errors"""
        try:
            return self.receive_message(ignore_eof=ignore_eof)
        except UBloxError as e:
            print(e)
            return None
        except OSError as e:
            # Occasionally we get hit with 'resource temporarily unavailable'
            # messages here on the serial device, catch them too.
            print(e)
            return None

    def send(self, msg):
        """send a preformatted ublox message"""
        if not msg.valid():
            self.debug(1, "invalid send")
            return
        if not self.read_only:
            self.write(msg._buf)

    def send_message(self, msg_class, msg_id, payload):
        """send a ublox message with class, id and payload"""
        msg = UBloxMessage()
        msg._buf = struct.pack('<BBBBH', 0xb5, 0x62, msg_class, msg_id, len(payload))
        msg._buf += payload
        (ck_a, ck_b) = msg.checksum(msg._buf[2:])
        msg._buf += struct.pack('<BB', ck_a, ck_b)
        self.send(msg)

    def configure_solution_rate(self, rate_ms=200, nav_rate=1, timeref=0):
        """configure the solution rate in milliseconds"""
        payload = struct.pack('<HHH', rate_ms, nav_rate, timeref)
        self.send_message(CLASS_CFG, MSG_CFG_RATE, payload)

    def configure_message_rate(self, msg_class, msg_id, rate):
        """configure the message rate for a given message"""
        payload = struct.pack('<BBB', msg_class, msg_id, rate)
        self.send_message(CLASS_CFG, MSG_CFG_SET_RATE, payload)

    def configure_port(self, port=1, inMask=3, outMask=3, mode=2240, baudrate=None):
        """configure a IO port"""
        if baudrate is None:
            baudrate = self.baudrate
        payload = struct.pack('<BBHIIHHHH', port, 0xff, 0, mode, baudrate, inMask, outMask, 0xFFFF, 0xFFFF)
        self.send_message(CLASS_CFG, MSG_CFG_PRT, payload)

    def configure_loadsave(self, clearMask=0, saveMask=0, loadMask=0, deviceMask=0):
        """configure configuration load/save"""
        payload = struct.pack('<IIIB', clearMask, saveMask, loadMask, deviceMask)
        self.send_message(CLASS_CFG, MSG_CFG_CFG, payload)

    def configure_poll(self, msg_class, msg_id, payload=''):
        """poll a configuration message"""
        self.send_message(msg_class, msg_id, payload)

    def configure_poll_port(self, portID=None):
        """poll a port configuration"""
        if portID is None:
            self.configure_poll(CLASS_CFG, MSG_CFG_PRT)
        else:
            self.configure_poll(CLASS_CFG, MSG_CFG_PRT, struct.pack('<B', portID))

    def configure_min_max_sats(self, min_sats=4, max_sats=32):
        """Set the minimum/maximum number of satellites for a solution in the NAVX5 message"""
        payload = struct.pack('<HHIBBBBBBBBBBHIBBBBBBHII', 0, 4, 0, 0, 0, min_sats, max_sats, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, 0)
        self.send_message(CLASS_CFG, MSG_CFG_NAVX5, payload)

    def module_reset(self, set, mode):
        """ Reset the module for hot/warm/cold start"""
        payload = struct.pack('<HBB', set, mode, 0)
        self.send_message(CLASS_CFG, MSG_CFG_RST, payload)

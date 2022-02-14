from dukpt import Server as DukptServer, InvalidDUKPTArguments
from Crypto.Cipher import DES3
from bitstring import BitArray

card_data = {"DeviceResponseData":{"Data":"000D31303030303033333534463030"},"BatteryLevel":100,"CapMagnePrint":"","CapMagnePrintEncryption":"","CapMagnePrint20Encryption":"00","CapMagneStripreEncryption":"1","CapMSR":"1","CapTracks":"95","CardDataCRC":0,"CardEncodeType":"00","CardExpDate":"2109","CardIIN":"417300","CardLast4":"1270","CardName":"916010051156252          /","CardPANLength":16,"CardServiceCode":"226","ResponseData":"00000050280000EC9107FC1098319325A3BA2341D701EA4112EA3562DAEA41172B5EE9E352EB9A9A27ED15CFEE9771FC5C51CF6B1A56A0B42BBE466F284FC508450231CD885CF38B90FBCA5A82C6C6A4F2C6830C2C672400000000000000000000000000000000000000000000000000000000000000001B11815FF223099220964B15D07EE591A3E761FEE4048A8F58D193096ABD67774E129F29D405EB8B000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061403000382493CB74636D0F884B98BF06A4A9D84A253243F1087CBED6FC11094493E2A5573524D23225FE5D76F5DF0A4D60BB63C62C7154EE39D67B430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004234303236443630313038313841410000069010010B4026D60001944921002542343137333030303032303030313237305E393136303130303531313536323532202020202020202020202F5E32313039323236303030303030303030303030303030303030303F0000000000000000000000000000000000000000000000000000000000000000000000000000003B343137333030303032303030313237303D32313039323236303030303030303F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004AE8F1B11C63A28D49210036FFFFFF5630350000000000153C05449D422FFCC7EF80C8CC325C0AF96126030300000000000000000000000000000000000000000000000000000000000000009010010B4026D600019464","DataFieldCount":0,"DeviceConfig":None,"DeviceName":"","DeviceSerial":"B4026D6010818AA","EncryptionStatus":"0006","Firmware":"1000003354F00","HashCode":"","KSN":"9010010B4026D6000194","MagnePrint":"2493CB74636D0F884B98BF06A4A9D84A253243F1087CBED6FC11094493E2A5573524D23225FE5D76F5DF0A4D60BB63C62C7154EE39D67B43","MagnePrintStatus":"61403000","MagTekDeviceSerial":"","MaskedTracks":"%B4173000020001270^916010051156252          /^21092260000000000000000000?;4173000020001270=21092260000000?","ResponseType":"","SwipeCount":-1,"TLVVersion":"","Track1":"EC9107FC1098319325A3BA2341D701EA4112EA3562DAEA41172B5EE9E352EB9A9A27ED15CFEE9771FC5C51CF6B1A56A0B42BBE466F284FC508450231CD885CF38B90FBCA5A82C6C6A4F2C6830C2C6724","Track1Masked":"%B4173000020001270^916010051156252          /^21092260000000000000000000?","Track2":"1B11815FF223099220964B15D07EE591A3E761FEE4048A8F58D193096ABD67774E129F29D405EB8B","Track2Masked":";4173000020001270=21092260000000?","Track3":"","Track3Masked":"","TrackDecodeStatus":"000000"}

device_serial = ""
card_swipe = {}
def get_data():

    decrypted_data = {}
    decrypted_data = decrypt_data()
    return decrypted_data

def get_decryption_key():
    return "0123456789ABCDEFFEDCBA9876543210"

def decrypt_data():
    bdk = BitArray(hex=get_decryption_key())
    result = {}
    if bdk:
        try:
            dukpt = DukptServer(bdk=bdk.bytes)
        except InvalidDUKPTArguments:
            return result
        ksn = BitArray(hex=card_swipe['card_data'].get("KSN"))
        #ksn: BitArray('0x9010010b4026d6000194')
        ipek = dukpt.generate_ipek(ksn=ksn)
        #ipek: BitArray('0x68f1c25711db82c44984e191b924bc32')
        # dukpt.derive_key: 0x608b5bba97e9a6ea5f19c94a21e36252
        session_key = dukpt.derive_key(ksn=ksn, ipek=ipek) ^ BitArray(
            hex="00000000000000FF00000000000000FF")
        try:
            data = BitArray(hex=card_swipe['card_data'].get('Track1'))
            cipher = DES3.new(session_key.bytes, DES3.MODE_CBC, BitArray(
                hex="0000000000000000").bytes)
            decrypted = cipher.decrypt(data.bytes)
        except ValueError:
            return result
        except AttributeError:
            return result

        track1 = bit_to_string(decrypted).split("^")
        # Checking whether decryption is success
        if len(track1) > 1:
            result = parse_decrypted_data(track1)

    return result

def bit_to_string(data):
    temp = str(data)
    return temp.replace("b'", "'")

def parse_decrypted_data(data):
    parsed_data = {}
    try:
        card_number = data[0].split("%B")[1]
        exp_year = data[2][:2]
        exp_month = data[2][2:4]

        parsed_data = {
            "DecryptedCardSwipe": {
                "card_number": card_number,
                "name": get_card_name(),
                "exp_month": exp_month,
                "exp_year": exp_year,
            }
        }
    except IndexError:
        pass

    return parsed_data

def get_card_name():
    name = card_swipe['additional_data'].get('CardName', '').strip()

    if name.endswith('/'):
        name = name.replace('/', '')
        name = name.strip()
    if '/' in name:
        name = [i.strip() for i in name.split('/')]
        name = ' '.join(reversed(name)).strip()

    return name

device_serial = card_data.get("DeviceSerial")
card_swipe = {
    'card_data': {
        'KSN': card_data.get('KSN', ''),
        "MagnePrint": card_data.get('MagnePrint', ''),
        'MagnePrintStatus': card_data.get('MagnePrintStatus', ''),
        'Track1': card_data.get('Track1', ''),
        'Track2': card_data.get('Track2', ''),
        'Track3': card_data.get('Track3', ''),
        'KeyType': 0
    },
    'additional_data': {
        'CardExpDate': card_data.get('CardExpDate', ''),
        'CardName': card_data.get('CardName', ''),
        'CardPANLength': card_data.get('CardPANLength', ''),
        'EncryptionStatus': card_data.get('EncryptionStatus', '')
    }
}
result = get_data()
print(result)

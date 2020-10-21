from Crypto.Cipher import AES
import hashlib
from binascii import hexlify, unhexlify


def pad(data):

    """
    ccavenue method to pad data.
    :param data: plain text
    :return: padded data.
    """

    length = 16 - (len(data) % 16)
    data += chr(length)*length
    return data


def unpad(data):

    """
    ccavenue method to unpad data.
    :param data: encrypted data
    :return: plain data
    """

    return data[0:-ord(data[-1])]


def encrypt(plain_text, working_key):

    """
    Method to encrypt cc-avenue hash.
    :param plain_text: plain text
    :param working_key: cc-avenue working key.
    :return: md5 hash
    """

    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    plain_text = pad(plain_text)

    byte_array_wk = bytearray()
    byte_array_wk.extend(map(ord, working_key))

    enc_cipher = AES.new(hashlib.md5(byte_array_wk).digest(), AES.MODE_CBC, iv)
    hexl = hexlify(enc_cipher.encrypt(plain_text)).decode('utf-8')

    return hexl


def decrypt(cipher_text, working_key):

    """
    Method decrypt cc-avenue response.
    :param cipher_text: encrypted data
    :param working_key: working data
    :return: list
    """
    cipher_text = '18f8dcf54eb96364648766f36929a396fbd25e0df06ceb1b5cf35a049c49cb6bcc9e836340fa66a2d15a75e7f4b78efbcd353a37c3888bacce04657f15bfd25e42ba4c0550175d113d568cd16f5a1bef0868f5fa15848de75f74d96a50251fe1014a91464bdeb1643b6ba108b8a9c6d52bf3fc6112c11a8c201e1eae294e4cfc33757a0e7dc484011c17b4322ddcf97cd6032c10d50b9045b2876bf82408af068b14682f2a82b40a7710c6a28b8f2ccccb8a26668761c6c0477c4c92beec8340d54390d6e51207d137f213454c5eb71b9ba5c21d618f0b81fa9123f55f3a88f4689bf7c1d69c81c5e1308621bf9a32c01afa05d252835d13d3debdc32b63929c01830f2be39beee49f8acc82618ca0ef633f6dd2f42491d494881f58d129fcab6eb6d6b4a21c0a659d1134df7fa8a1108c63f6b15205aa6ed54f6be13c0de272ab51d81d602a685204928ababe796b7c02846656e7ad23a0b4c5cc0d4fe3ad9cd99659afca0d2c0de2d33e7ec5861b8a7dd0094dcaf24b3f61188979affed9470dad3f17e8f331cec5b7a2b4e018b49ba4a8f6a059cb02539d6b0bc0de1b3e2e108fbade9b8c9a893e210cc127e41f7602b74f398a73375571d6cf6c05bcd66fe079b416359a392901fe197c33f08c08d9a76a6fcc2c104ac61f00f38b417d17236f832a6731dbf548caa1724c676d6b469cebc9b513ce640c0b8474b5eaac381f2cd61bf5b8aa28182c82a6fb71e2f03c426001f535157dd3a30d2b1be26b92e0f44b73ffc719a897deca335a8bc8fa59218ce6dcd53dcfb3122e3662d6523ecde345bdde8ee72e730159a7016dc70f3beb2c36e0031bd23fc3d33b81598f1e2d5815bb8b5752f238e3977d5ff372dc72002d6c8e1b19c31e1a0eb33829346cdee3679d5a24a94f62e7c13c28db644e6886c1abf41101f13e900713aa76be05f3d598f7d3375a31091bc5585e78f09edbb093ff6abf9fe29fe91eb114e39fd4f3075b30c284c349e55744e38ffdea97ba4cf2737ee18cf26607871b0c585903735dd07c76ca9d1210c4ec1a38bced7c26940c80c3f1ff65c06157d9cbf4edf9d8eef8805df5e4aaeb785fe567162ed41fbf49fb8dd188b87477fc68370ccd2b4dd0aa0c54bd4bc09ed0bb90bbd8beda88d038b80bee72a17d6ad59e2719eeda72b788f862b0764fda970a4342d0b372d67e3de99c313b9cf15faf31d61c0876fa2d58bb1597dd0525b61f6ae40ea7a6a1b544cdec600d6a070327194fd74469fcf3993e2f15685074b34e70c1e0a04aeab950cdf4c2ed9f287360227fe16ca84aab9f7b2916690b960b170dffb3f54e8390b170fd8fc8785b687832c0a7a48a'
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

    encrypted_text = unhexlify(cipher_text)

    bytearray_working_key = bytearray()
    bytearray_working_key.extend(map(ord, working_key))

    dec_cipher = AES.new(hashlib.md5(bytearray_working_key).digest(), AES.MODE_CBC, iv)

    plain_data = unpad(dec_cipher.decrypt(encrypted_text).decode('utf-8'))

    plain_data_list = plain_data.split('&')

    final_pay_list = []
    for data in plain_data_list:

        final_pay_dict = {}
        final_pay_dict[data.split('=')[0]] = data.split('=')[1]

        final_pay_list.append(final_pay_dict)

    return final_pay_list

import time
from pn532 import PN532_I2C

class NFCReader:
    def __init__(self, i2c_bus=1, i2c_address=0x24, debug=False):
        """Инициализация NFC модуля PN532"""
        self.debug = debug
        try:
            self.pn532 = PN532_I2C(i2c_bus=i2c_bus, address=i2c_address, debug=debug)
            ic, ver, rev, support = self.pn532.get_firmware_version()
            if self.debug:
                print(f"Found PN532 with firmware version: {ver}.{rev}")
            self._configure_reader()
        except Exception as e:
            print(f"PN532 initialization error: {str(e)}")
            raise

    def _configure_reader(self):
        """Настройка параметров чтения"""
        self.pn532.SAM_configuration()

    def read_uid(self, timeout=1.0):
        """Чтение UID карты (блокирующий вызов)"""
        try:
            uid = self.pn532.read_passive_target(timeout=timeout)
            if uid is not None and self.debug:
                print(f"Found card with UID: {[hex(i) for i in uid]}")
            return uid
        except Exception as e:
            if self.debug:
                print(f"Read error: {str(e)}")
            return None

    def read_data(self, block_number):
        """Чтение данных из указанного блока (Mifare 1K)"""
        if not self._authenticate_block(block_number):
            return None
        
        try:
            data = self.pn532.mifare_classic_read_block(block_number)
            if data is not None and self.debug:
                print(f"Block {block_number} data: {data.hex()}")
            return data
        except Exception as e:
            if self.debug:
                print(f"Read block error: {str(e)}")
            return None

    def write_data(self, block_number, data):
        """Запись данных в указанный блок (16 байт)"""
        if len(data) != 16:
            raise ValueError("Data must be exactly 16 bytes")
        
        if not self._authenticate_block(block_number):
            return False
        
        try:
            self.pn532.mifare_classic_write_block(block_number, data)
            if self.debug:
                print(f"Data written to block {block_number}")
            return True
        except Exception as e:
            if self.debug:
                print(f"Write block error: {str(e)}")
            return False

    def _authenticate_block(self, block_number, key=None):
        """Аутентификация блока (по умолчанию ключ A)"""
        uid = self.read_uid()
        if uid is None:
            return False
        
        default_key = b'\xFF\xFF\xFF\xFF\xFF\xFF'  
        key = key or default_key
        
        try:
            authenticated = self.pn532.mifare_classic_authenticate_block(
                uid, block_number, 0x60, key)
            return authenticated
        except Exception as e:
            if self.debug:
                print(f"Authentication error: {str(e)}")
            return False

    def cleanup(self):
        """Корректное завершение работы"""
        if hasattr(self, 'pn532'):
            self.pn532.close()

if __name__ == "__main__":
    # Пример использования
    nfc = NFCReader(debug=True)
    try:
        while True:
            print("Waiting for NFC card...")
            uid = nfc.read_uid()
            if uid:
                print(f"Card UID: {[hex(i) for i in uid]}")
                
                # Чтение блока 4
                data = nfc.read_data(4)
                if data:
                    print(f"Block 4 data: {data.hex()}")
                
                time.sleep(2)
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        nfc.cleanup()
#sudo apt-get install python3-pip
#sudo pip3 install adafruit-circuitpython-pn532


import board
import busio
from digitalio import DigitalInOut
from adafruit_pn532.spi import PN532_SPI

# Настраиваем SPI шину
spi = busio.SPI(board.SCK, board.MOSI, board.MISO)

# Настраиваем пин CS (Chip Select)
# Используем пин 24 (board.CE0) для SPI1_CS0
cs_pin = DigitalInOut(board.CE0)

# Инициализируем PN532
try:
    pn532 = PN532_SPI(spi, cs_pin, debug=False)
    ic, ver, rev, support = pn532.firmware_version
    print("Найден чип PN532!")
    print(f"Версия прошивки: {ver}.{rev}")
except Exception as e:
    print("Ошибка при подключении к PN532:", e)
    exit()

# Настраиваем для прослушивания карт
pn532.SAM_configuration()

print("Жду NFC карту/метку...")

while True:
    # Проверяем наличие карты
    uid = pn532.read_passive_target(timeout=0.5)
    # Если ничего нет, uid будет None
    if uid is None:
        continue
    
    print("Найдена карта с UID:", [hex(i) for i in uid])
    break

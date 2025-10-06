#!/bin/bash
echo "Удаление папок logs и data..."

if [ -d "logs" ]; then
    echo "Удаляю папку logs..."
    rm -rf logs
    echo "✓ Папка logs удалена"
else
    echo "✓ Папка logs не существует"
fi

if [ -d "data" ]; then
    echo "Удаляю папку data..."
    rm -rf data
    echo "✓ Папка data удалена"
else
    echo "✓ Папка data не существует"
fi

echo "Готово! Все папки удалены."
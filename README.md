
# file-crypt

Библиотека и CLI-утилита на C++20 для симметричного шифрования файлов (AES-256-CBC),
безопасного обмена ключами (RSA-2048) и проверки целостности (SHA-256).

## Сборка

1. Клонирование репозитория

```
git clone https://github.com/<you>/AES_RSA_Crypto.git
cd AES_RSA_Crypto
```

2. Сборка проекта

```
cmake .. `                          
-G "Visual Studio 17 2022" `
-A x64 `
-DCMAKE_TOOLCHAIN_FILE="C:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake" `
-DVCPKG_TARGET_TRIPLET="x64-windows"
```
---

```
cmake --build . --config Release
```

```
cd ./build/Release
```

3. Запуск тестов

```
ctest -C Release --output-on-failure
```

4. Удаление сборки

```
cd ../..
rm -r build
```

5. CLI
Создание папки с вашим секретным файлом

```
cd ./build/Release
mkdir data; cd data
```

В этой папке создаете текстовый файл in.txt с любым наполнением, как в примере команд далее или же в нее добавляете любой файл, который будете использовать в зашифровке.

---

Генерация пары RSA-ключей: Private и Public

```
.\filecrypt_cli.exe genkeys <имя пользователя>
```

---

Генерация случайного 32-битного raw-ключа

```
.\filecrypt_cli.exe genrawkey key.bin
```

---

AES-шифрования нашего файла с использованием созданного raw-ключа

```
.\filecrypt_cli.exe encrypt_with_key key.bin data\in.txt data\out.enc
```

---

AES-обертывание raw-ключа при помощи публичного RSA-ключа

```
.\filecrypt_cli.exe wrapkey key.bin <имя публичного ключа>.pem wrapped.bin
```

---

Развертывание зашифрованного raw-ключа при помощи приватного RSA-ключа

```
.\filecrypt_cli.exe unwrapkey wrapped.bin <имя приватного ключа>.pem key_recovered.bin
```

---

AES-десшифровка нашего файла развернутым raw-ключом

```
.\filecrypt_cli.exe decrypt_with_key key_recovered.bin data\out.enc data\recovered.txt
```

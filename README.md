# Инструкция по ЛР №15 Протокол директорий LDAP
## Конфигурация сетевых карт ВМ:
 - Виртуальные сети VBox:
   - Host-Network:
     - IP: 192.168.0.254
     - Mask: 255.255.255.0
     - DHCP: disabled
 - ВМ1:
   - enp0s3(NAT/bridge) -> интернет для скачивания пакетов
   - enp0s8(подключен к HostNetwork)
     - IP: 192.168.0.1/24
     - Gate: 192.168.0.254
 - ВМ2:
   - enp0s3(NAT/bridge) -> интернет для скачивания пакетов
   - enp0s8(подключен к HostNetwork)
     - IP: 192.168.0.2/24
     - Gate: 192.168.0.254
 - ВМ3:
   - enp0s3(NAT/bridge) -> интернет для скачивания пакетов
   - enp0s8(подключен к HostNetwork)
     - IP: 192.168.0.3/24
     - Gate: 192.168.0.254
---
## 1. Запустить и настроить сервер openLDAP на ВМ2
### Основные значения LDAP:
 - База данных: mad.net
 - Данные администратора базы: admin:secret
 - IP адрес сервера: 192.168.0.1
---
### Действия ВМ2:
 - Настраиваем IP адреса: `nano /etc/network/interfaces`
    ```conf
    auto enp0s3
    iface enp0s3 inet dhcp

    auto enp0s8
    iface enp0s8 inet static
    address 192.168.0.1/24
    gateway 192.168.0.254
    ```
 - Применяем изменения:\
 `systemctl restart networking`
 - Проверим подключение к интернету:\
 `ping 8.8.8.8`
 - Проверим подключение к Host-Network:\
 `ping 192.168.0.254`
 - Обновляемся:\
 `apt update && apt upgrade -y`
   - `/dev/sda` - место установки GRUB
 - Установим slapd(Standalone LDAP Daemon) и утилиты управления LDAP:\
 `apt install slapd ldap-utils -y`
   - `secret` - пароль админа LDAP
   - `secret` - подтверждение
 - Теперь настроим slapd, вводим:\
 `dpkg-reconfigure slapd`
   - `No` - создаем новую конфигурацию
   - `mad.net` - доменное имя
   - `mad` - название организации
   - `secret` - пароль админа LDAP
   - `secret` - подтверждение
   - `MDB` - тип бэкэнда
   - `No` - если удалить slapd, база останется
   - `Yes` - подтверждаем изменения
 - Чтобы проверить, что сервер запущен:\
 `systemctl status slapd`
## 2. Добавить 2х пользователей и 2 группы (числовые идентификаторы выбрать более 10000) в LDAP.
### Дерево LDAP:
  ```
  dc[mad.net]
    |      
    ou[Users]
    | |
    | uid[{10011}user1:Password1] <-+
    | uid[{10022}user2:Password2] <-|-+
    |                               | |
    ou[Groups]                      | |
      |                             | |
      gid[{10010}office] <----------+ |
      gid[{10020}direct] <------------+
  ```
---
### Действия ВМ2:
 - Чтобы управлять записями, используют файлы с расширением LDIF.
 - В `nano ounits.ldif` вводим юниты `Groups` и `Users`, для хранения групп и пользователей:
    ```ldif
    dn: ou=Groups,dc=mad,dc=net
    objectClass: organizationalUnit
    ou: Groups
    
    dn: ou=Users,dc=mad,dc=net
    objectClass: organizationalUnit
    ou: Users
    ```
 - В `nano pgroups.ldif` добавим группы `office` и `direct`, поместив их в юнит `Groups`:
    ```ldif
    dn: cn=office,ou=Groups,dc=mad,dc=net
    objectClass: posixGroup
    cn: office
    gidNumber: 10010
    
    dn: cn=direct,ou=Groups,dc=mad,dc=net
    objectClass: posixGroup
    cn: direct
    gidNumber: 10020
    ```
 - В `nano pusers.ldif` добавим юзеров `user1` и `user2`, поместив их в юнит `Users` и распредлив по группам `office` и `direct` соответственно:
    ```ldif
    dn: uid=user1,ou=Users,dc=mad,dc=net
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    uid: user1
    sn: Users
    cn: Office
    uidNumber: 10011
    gidNumber: 10010
    homeDirectory: /home/user1
    loginShell: /bin/bash
    userPassword: {crypt}x
    
    dn: uid=user2,ou=Users,dc=mad,dc=net
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    uid: user2
    sn: Users
    cn: Direct
    uidNumber: 10022
    gidNumber: 10020
    homeDirectory: /home/user2
    loginShell: /bin/bash
    userPassword: {crypt}x
    ```
  ВАЖНО: перепроверь каждый файл дважды, перед тем, как вводить его, он полностью должен соответствовать, каждый блок отделен отступом, не должно быть опечаток.\
  Если не уверен, сделай снапшот!
 - Файлы готов, вводим их поочередно в БД от имени админа LDAP'a (пароль: `secret`):\
 `ldapadd -x -D cn=admin,dc=mad,dc=net -W -f ounits.ldif -v`\
 `ldapadd -x -D cn=admin,dc=mad,dc=net -W -f pgroups.ldif -v`\
 `ldapadd -x -D cn=admin,dc=mad,dc=net -W -f pusers.ldif -v`
 - Используя `ldapsearch` для проверки можно вывести любые данные, например получить все записи:\
 `ldapsearch -x -LLL -b dc=mad,dc=net`
 - Осталось добавить пароль для `user1`:`Password1`:\
 `ldappasswd -s Password1 -W -D cn=admin,dc=mad,dc=net -x "uid=user1,ou=Users,dc=mad,dc=net"`
   - `secret` - пароль админа
 - Пароль для `user2`:`Password2`:\
 `ldappasswd -s Password2 -W -D cn=admin,dc=mad,dc=net -x "uid=user2,ou=Users,dc=mad,dc=net"`
   - `secret` - пароль админа
 - Чтобы проверить, что пароли добавились:\
 `ldapsearch -x -W -D cn=admin,dc=mad,dc=net -b "uid=user1,ou=Users,dc=mad,dc=net" "(objectclass=*)"` - вместо {crypt}x, видим шифр
## 3. Настроить ВМ1, ВМ2 и ВМ3 так, чтобы они идентифицировали и аутентифицировали пользователей через OpenLDAP с ВМ2.
### Топология сети:
  ```
  Server:VM2[192.168.0.1/24]
        |
        |
  Gateway:vboxnet0[192.168.0.254/24]
    |      |
    | Client:VM1[192.168.0.2/24]
    |   
  Client:VM3[192.168.0.3/24]
  ```
---
### Действия ВМ1:
 - Настроим сеть: `nano /etc/network/interfaces`\
    ```conf
    auto enp0s3
    iface enp0s3 inet dhcp

    auto enp0s8
    iface enp0s8 inet static
    address 192.168.0.2/24
    gateway 192.168.0.254
    ```
    - `systemctl restart networking`
---
### Действия ВМ3:
 - Настроим сеть: `nano /etc/network/interfaces`
    ```conf
    auto enp0s3
    iface enp0s3 inet dhcp

    auto enp0s8
    iface enp0s8 inet static
    address 192.168.0.3/24
    gateway 192.168.0.254
    ```
 - `systemctl restart networking`
---
### Действия ВМ1 и ВМ3:
 - Проверяем:
    - `ping 8.8.8.8` - интернет
    - `ping 192.168.0.1` - LDAP сервер
 - Обновимся:\
 `apt update && apt upgrade -y`
   - `/dev/sda` - место установки GRUB
---
### Действия для всех машин по очереди:
 - Ставим необходимые пакеты:\
 `apt install libnss-ldap libpam-ldap nscd ldap-utils -y`
   - `ldap://192.168.0.1` - IP адрес сервера
   - `dc=mad,dc=net` - база
   - `3` - версия LDAP
   - `cn=admin,dc=mad,dc=net` - админ сервера
   - `secret` - его пароль
   - `Yes` - использовать PAM
   - `No` - необязательный логин
   - `cn=admin,dc=mad,dc=net` - админ сервера
   - `secret` - его пароль
 - Чтобы установить соединение c базой данных, нужно просто добавить ссылку на сервер в файл: `ldap.conf`:\
 `echo 'URI ldap://192.168.0.1' >> /etc/ldap/ldap.conf`
 - Теперь мы можем выполнить для проверки:\
 `ldapsearch -x -LLL -b dc=mad,dc=net`
 - Добавим эти строчки в файл: `nano /etc/nsswitch.conf` , чтобы искать юзеров в LDAP:
  ```conf
  passwd: files ldap
  shadow: files ldap
  group: files ldap
  ```
 - Настроим автосоздание домашнего каталога для пользователей:\
 `echo 'session required pam_mkhomedir.so skel=/etc/skel umask=077' >> /etc/pam.d/common-session`
 - Перезапускаем nscd:\
 `systemctl restart nscd`
 - Чтобы проверить:\
 `getent passwd | grep user` - должны получить двух LDAP юзеров, можем войти через них на ВМ.
## 4. Разрешить только пользователям из первой LDAP группы входить в ВМ1.
---
### Действия ВМ1:
 - Входим под `root`
 - Добавим правило проверки входящих пользователей в PAM:\
 `echo 'auth required pam_access.so' >> /etc/pam.d/common-auth`
 - Впишем правило входа на машину в файл, к которому обращается модуль `pam_access.so`:\
 `echo '-:ALL EXCEPT root office:ALL EXCEPT localhost' >> /etc/security/access.conf` (запретить всем вход кроме root и office групп, из не локальной учетки)
 - Проверяем:\
 `logout` -> `user2` -> `Password2` - получаем login incorrect
## 5. Запретить доступ к LDAP без SSL.
---
### Действия ВМ2:
 - Установим утилиту для удобного создания сертификатов:\
 `apt install gnutls-bin -y`
 - Создаем приватный ключ:\
 `certtool --generate-privkey --outfile /etc/ssl/private/ldap-key.pem`
 - Создаем самоподписанный сертификат:\
 `certtool --generate-self-signed --load-privkey /etc/ssl/private/ldap-key.pem --outfile /etc/ssl/certs/ldap-cert.pem`\
 ВАЖНО: отвечаем на все вопросы просто Enter, КРОМЕ:\
 `Common name`: `LDAP.mad.net`\
 `The certificate will expire in (days)`: `365`\
 `Does the certificate belong to an authority? (y/N)`: `N`\
 `Enter the IP address of the subject of the certificate`: `200.200.200.200`\
 В конце ВНИМАТЕЛЬНО, после того, как покажет превью сертификата, на вопрос:\
 `Is the above information ok? (y/N)`: `y`
 - Добавляем ldap юзера в группу ssl-cert:\
 `adduser openldap ssl-cert`
 - Ставим права на сертификат и ключ, доступ из группы `ssl-cert`, только чтение:\
 `chgrp ssl-cert /etc/ssl/private/ldap-key.pem`\
 `chgrp ssl-cert /etc/ssl/certs/ldap-cert.pem`\
 `chmod g+r /etc/ssl/private/ldap-key.pem`\
 `chmod g+r /etc/ssl/certs/ldap-cert.pem`
 - Создаем LDIF файл, чтобы добавить записи о сертификатах в конфиг: `nano ssl.ldif`
    ```ldif
    dn: cn=config
    changetype: modify
    add: olcTLSCipherSuite
    olcTLSCipherSuite: NORMAL
    -
    add: olcTLSCRLCheck
    olcTLSCRLCheck: none
    -
    add: olcTLSVerifyClient
    olcTLSVerifyClient: never
    -
    add: olcTLSCertificateFile
    olcTLSCertificateFile: /etc/ssl/certs/ldap-cert.pem
    -
    add: olcTLSCertificateKeyFile
    olcTLSCertificateKeyFile: /etc/ssl/private/ldap-key.pem
    ```
ВАЖНО: перепроверь файл дважды, перед тем, как вводить его, он полностью должен соответствовать, каждый блок в строгом порядке, не должно быть опечаток.\
Если не уверен, сделай снапшот!
 - Меняем имя сервера, на то, которое указали в сертификате (LDAP.mad.net): `hostnamectl set-hostname "LDAP.mad.net"`
 - Перезагружаем сервер: `reboot`
 - Загружаем файл `ssl.ldif` на сервер:\
 `ldapmodify -Y EXTERNAL -H ldapi:/// -f ssl.ldif`
 - Проверим наличие этих записей:\
 `slapcat -b cn=config | grep olcTLS`
 - Добавляем поддержку LDAPSSL (636 порт) на сервер, заодно убираем LDAP без SSL (389 порт), запретив незащищенные подключения:\
 `sed -i -e 's/SLAPD_SERVICES="ldap:\/\/\/ ldapi:\/\/\/"/SLAPD_SERVICES="ldapi:\/\/\/ ldaps:\/\/\/"/' /etc/default/slapd`
 - Перезапускаем демон: `systemctl restart slapd`
 - Проверяем порты:
   - `netstat -ntl | grep 389` - ничего не должно быть
   - `netstat -ntl | grep 636` - порты открыты
---
### Действия для всех машин по очереди:
 - С этого момента мы не можем получить доступ к БД LDAP и аутентифицироваться:\
 `ldapsearch -x -LLL -b dc=mad,dc=net` - ошибка\
 `getent passwd | grep user` - пусто
 - Первым делом восстановим доступ к БД: `nano /etc/ldap/ldap.conf`
    ```conf
    URI ldap://192.168.0.1
    меняем на
    URI ldaps://192.168.0.1
    TLS_REQCERT allow
    ```
    - последнее правило, отвечает за пропуск даже, если сертификат не прошел верификацию(обязательно для самоподписанных SSL сертификатов)
 - Таким образом `ldapsearch` уже получает данные
 - Пофиксим настройки NSS:\
 `dpkg-reconfigure libnss-ldap`
   - `ldaps://192.168.0.1` - меняем протокол на защищенный
   - `dc=mad,dc=net` - все остальное, как было
   - `3`
   - `No`
   - `Yes`
   - `No`
   - `cn=admin,dc=mad,dc=net`
   - `secret`
   - `Ok`
 - Теперь перенастроим аутентификацию:\
 `dpkg-reconfigure libpam-ldap`
   - `ldaps://192.168.0.1` - меняем протокол на защищенный
   - `dc=mad,dc=net` - все остальное, как было
   - `3`
   - `Yes`
   - `No`
   - `cn=admin,dc=mad,dc=net`
   - `secret`
   - `crypt` - метод шифрования паролей пользователей
   - `Ok`
 - Чтобы проверить можно ввести:\
 `getent passwd | grep user` - получим наших юзеров, можем `Ctrl-D` и залогиниться.

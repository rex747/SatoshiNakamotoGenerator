Русский:
Данная программа – одна из не многих программ, основанных не только на предположениях о том, как генерировались первые адреса Биткоин у создателя Bitcoin, а еще и на проведенных исследованиях OSINT, целью которых было максимальное восстановление источников энтропии генерации первых кошельков Bitcoin.
Как известно, Windows XP SP-3 вышла в 2008 году и использовала одну из версий линейных конгруэнтных генераторов (LCG). Данные генераторы для энтропии осуществляли сбор системных данных, который не превышал 5 443 988 736 возможных вариантов, что согласитесь, гораздо меньше, чем значение 2256 .
Если мы проанализируем имеющийся на сегодняшний день код Bitcoin ver. 0.1.0, то мы обнаружим, что к энтропии, создававшейся LCG генератором, создатель Bitcoin добавил энтропию текущего времени (не зря же в блокчейне присутствует «Timestamp») и медианного значения времени.
Осталось понять, каким было значение времени, когда началась генерация Bitcoin адресов? При помощи исследований OSINT (и имеющиеся сведения являются «ноу-хау»), удалось установить, что генерация первых адресов Bitcoin началась не 9 января 2009 года.
Таким образом, удалось создать программу, восстанавливающую генерацию энтропии первых Bitcoin адресов.
По причине того, что данная программа содержит сведения, полученные при помощи исследований OSINT, начальные значения времени в релизе на GitHub отсутствуют и получить программу с данными значениями возможно, оплатив ее покупку.
Для каждого клиента программа будет скомпилирована индивидуально. Возможно обсуждение персональных настроек программы с каждым клиентом.
Поскольку, данный релиз программы осуществляет простой брутфорс в заданном диапазоне, стоимость программы составляет 500$.

Минимальные системные требования.
Windows 10.
Процессор: 3.00 GHz.
Оперативная память: 8 Гб.
HDD: от 100 Гб

Особенности:
- соединение Интернет не требуется, как видно из кода на GitHub, программа сведения третьим лицам не поставляет, сбор данных не осуществляет;
- скорость около 1500 значений в секунду (зависит от комплектации компьютера);
- создает два файла базы данных: «addresses.txt» и «generated.txt», файл «addresses.txt» используется для поиска через блюм-фильтр, файл «generated.txt» - содержит все сгенерированные приватные ключи и адреса;
- генерирует адреса в формате P2PKH, что соответствует первым адресам Bitcoin, содержащим как раз, искомые 50 BTC.

Условия приобретения:
- оплата 500$ покупки программы на адрес Monero: 45YP8PgLwDEcw4vMBQCLwC11qzPti8ypaRTuJeuxfZhJfhoVXmSGmU4jUSnDtdwcLxQAVzjxbFHmHNNm5U2kUeuDMAWGH9T
- после оплаты, написать письмо по адресу: rex747@protonmail.com  с указанием адреса, с которого была произведена оплата, и Вам будет выслана скомпилированная стандартная программа, либо скорректированная за + 200$ за каждый пункт Ваших пожеланий (если требуется доработка кода, процесс может занять от 1 до 5 дней).

В следующей версии программы: 
- генерация приватных ключей «узкой направленности»;
- новый блюм-фильтр;

Лицензия:
MIT.

English:
Program Description
This program is one of the few tools not solely based on assumptions about how Bitcoin's creator generated the earliest Bitcoin addresses but also on OSINT research aimed at reconstructing the entropy sources used in the creation of the first Bitcoin wallets.

As is known, Windows XP SP-3 was released in 2008 and utilized a version of a Linear Congruential Generator (LCG) for entropy. These LCGs collected system data, resulting in a maximum of 5,443,988,736 possible values—significantly fewer than the expected 2²⁵⁶.

An analysis of Bitcoin v0.1.0 code reveals that the creator supplemented the LCG's entropy with current time entropy (hence the presence of "Timestamp" in the blockchain) and median time values.

The remaining question was: What was the exact time when Bitcoin address generation began? Through OSINT research (proprietary findings), it was determined that the first Bitcoin addresses were not generated on January 9, 2009.

Thus, this program was developed to reconstruct the entropy generation of the earliest Bitcoin addresses.

Due to the inclusion of OSINT-derived data, the initial time values are omitted from the GitHub release. To obtain the program with these values, a purchase is required.

Each client receives a custom-compiled version. Personalized configurations can be discussed individually.

Since this release performs a basic brute-force search within a defined range, the program is priced at $500.

Minimum System Requirements

OS: Windows 10

CPU: 3.00 GHz

RAM: 8 GB

Storage: 100 GB HDD

Key Features

No internet connection required (as visible in the GitHub code)—the program does not transmit data to third parties or collect any information.

Speed: ~1,500 values per second (varies by hardware).

Generates two database files:
addresses.txt – Used for Bloom filter searches.
generated.txt – Contains all generated private keys and addresses.

Generates P2PKH addresses, matching the format of the earliest Bitcoin addresses (including those holding the original 50 BTC).

Purchase Terms:

Payment:
$500 (in Monero) to the following address:

45YP8PgLwDEcw4vMBQCLwC11qzPti8ypaRTuJeuxfZhJfhoVXmSGmU4jUSnDtdwcLxQAVzjxbFHmHNNm5U2kUeuDMAWGH9T  

Confirmation:
After payment, send an email to rex747@protonmail.com with:
The sender’s Monero address (used for payment).
You will then receive:
A standard compiled version of the program, or
A customized version (+$200 per requested modification, if code modifications are required, the process may take 1 to 5 days).

Planned Updates

-	targeted private key generation;
-	improved Bloom filter implementation.

License:
MIT License

# Web Siteleri Ve Guvenlik



## CORS (Cross-Origin Resource Sharing)(Kökenler arası kaynak paylaşım)


CORS , web sitelerinin farklı domainlerden gelen isteklere nasıl yanıt vereceğini belirleyen bir güvenlik mekanizmasıdır.
Web sitesi,  tarayıcıdan  farklı bir kökene ( bu domain, protokol ve port olabilir) herhangi bir istek gönderirse cross-origin HTTP isteği oluşturmuş olur.

Örnek CORS hata mesajı:

![](./assets/Cors.png "GitHub")



Not: Origin, bir web sayfasının kaynağını tanımlayan bir terimdir.

1.Protokol (HTTP, HTTPS)

2.Domain (www.bugra.com)

3.Port (8080, 8000, vb.)

Bu üç bileşen birlikte origin'i oluşturur.

    <protokol>://<domain>:<port>

--------
    https://www.bugra.com




Örneğin, http://bugra.com üzerinde yer alan bir web uygulamasının JavaScript tarafından  istek göndererek, http://bugrab.com‘a erişmesi bir cross origin isteğidir.

Web tarayıcıları, **SOP (Same-Origin Policy) (Aynı Kaynak Politikası)** adı verilen bir güvenlik politikası uygular. Bu politika, bir web sayfasının yalnızca kendi kaynağındaki (aynı protokol, domain ve porttan gelen) verilere erişmesine izin verir. Bir web sitesinin başka bir web sitesinden özel verileri çalması gibi potansiyel olarak kötü niyetli işlemleri engellemek için tasarlanmıştır. Genel olarak, bir alanın diğer alanlara istek göndermesine izin verir, ancak yanıtları erişmesine izin vermez. **CORS**, bu kısıtlamayı belirli siteler için kaldırarak, farklı kökenlerden gelen isteklere izin verir.

İki origin’in aynı olabilmesi için protokol, domain ve port bilgilerinin aynı olması gerekir. Yani iki adres bilgisi aynı olduğunda, farklı port değerlerine sahiplerse **same-origin** olmazlar.

![photo by xBugOR](./assets/CORS.drawio.png
 "GitHub")

**Aynı adreslere farklı kaynaklardan erişim**



CORS Nasıl Çalışır?
Temel CORS Başlıkları:

**Access-Control-Allow-Origin** → Hangi domain'lerin erişebileceğini belirler.

**Access-Control-Allow-Methods** → Hangi HTTP metodlarının (GET, POST, PUT, DELETE vb.) kullanılabileceğini belirler.

**Access-Control-Allow-Headers**→ Gönderilen özel başlıkların (headers) hangilerinin kabul edileceğini tanımlar.

**Access-Control-Allow-Credentials** → Tarayıcının kimlik doğrulama bilgilerini (çerez, HTTP kimlik doğrulaması vb.) iletip iletemeyeceğini belirler.

**Access-Control-Max-Age**→ Tarayıcının önceden yapılan bir isteğin CORS bilgisini ne kadar süreyle saklayacağını belirtir.

Örnek Senaryo:


- Fronted uygulamamız https://frontend.com domaininde çalışıyor. 

- Bu fronted backenddeki bir API bağlanacak.

- Backendin domaini farklı https://api.backend.com.

Şimdi, tarayıcı bu iki farklı origin'i fark ettiği için, CORS devreye girecek. Eğer backend tarafında CORS ayarları yapılmazsa, frontend'in API'ye yaptığı istekler tarayıcı tarafından engellenir.

Başka bir origine atılan isteklerden önce tarayıcı OPTIONS isteğini gönderirir. Karşı tarafın yapılmak istenen isteğe izin verip vermediğini anlar.

1. CORS İstek (Preflight Request)
```http
OPTIONS /api/data HTTP/1.1
Host: api.backend.com
Origin: https://frontend.com
Access-Control-Request-Method: GET
```


✅ "Ben /api/data endpoint'ine erişmek istiyorum ama önce izin alayım."


✅ "Bu isteği api.backend.com adlı sunucuya gönderiyorum."

✅ "Ben https://frontend.com adlı siteden geliyorum, bana izin verir misin?"

✅ "Ben GET metodu kullanarak veri çekmek istiyorum. Buna izin var mı?"

Endpoint(veri almak, göndermek veya değiştirmek için API'ye yaptığı isteğin hedef noktasıdır.)

2. Backend'den Cevap

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://frontend.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
```

✅ "İstek başarılı oldu!"

✅ "Sadece https://frontend.com adresinden gelen isteklere izin veriyorum."

✅ "GET, POST ve PUT metodlarıyla gelen isteklere izin veriyorum."

✅ "Sadece Content-Type ve Authorization başlıklarını içeren isteklere izin veriyorum."

3. Asıl İstek
```http

GET /api/data HTTP/1.1
Host: api.backend.com
Origin: https://frontend.com
Authorization: Bearer <token>
```

✅ "Ben /api/data endpoint'inden veri almak istiyorum."

✅ "Bu isteği api.backend.com adresine gönderiyorum."

✅ "Bu isteği https://frontend.com adresindeki bir frontend uygulamasından gönderiyorum."

✅ "Kimliğimi doğrulamak için bir Bearer Token gönderiyorum."


```http

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": "Data burda!"
}
```
✅ "İstek başarılı oldu!"

✅ "Bu yanıtın içeriği JSON formatında!"

✅ "Burada JSON formatında bir veri var."
 
 İzin vermezse

```http

 HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "Yetkisiz erişim!"
}
```


Not:
Bazı istekler preflight  isteklerine ihtiyaç duymayabilir.


## XSS (Cross-Site Scripting) Saldırıları

XSS (Cross-Site Scripting), bir saldırganın, kullanıcılar tarafından görüntülenen bir web sayfasına zararlı JavaScript kodları enjekte etmesine denir.

Genellikle formlar, yorum kutuları, URL parametreleri veya yerel depolama alanları gibi kullanıcıların bilgi girişi yaptığı alanlara etki ederler.

Genellikle bu açıkta kullanıcıların girdiği bilgilerin doğrulanması ve şifrelenmesi işlemleri  yapılmaz.


#### XSS'in Genel Çalışma Prensibi:

1.Saldırgan, zararlı bir JavaScript kodu gönderir

2.Web uygulaması bu zararlı kodu uygun şekilde temizlemeden veya kodlamadan kullanıcının tarayıcısına yansıtır.

3.Tarayıcı, gelen bu zararlı kodu çalıştırır ve saldırgan, hedeflenen kullanıcıyı etkiler.


Temel olarak böyle çalışıyor.


## XSS Türleri
### Reflected XSS

Saldırganın zararlı JavaScript kodunu anlık olarak bir URL veya form verisi üzerinden yansıttığı saldırı türüdür.

Kullanıcının girdiği veri direkt olarak kendisine geri döndürülür ve arka planda zararlı kodlar çalıştırılır.

Depolanmaz.Kullanıcı özelinde çalışır ve zararlı linkler üzerinden yayılır.

### Bu saldırı ile neler yapılabilir ?

🔴Kullanıcının gerçekleştirebileceği herhangi bir eylemi uygulama içinde gerçekleştirmek. 

🔴Kullanıcının görebileceği herhangi bir bilgiyi görüntülemek. 

🔴Kullanıcının değiştirebileceği herhangi bir bilgiyi değiştirmek. 

🔴İlk kurban kullanıcıdan geliyormuş gibi görünecek şekilde diğer uygulama kullanıcılarıyla etkileşim başlatmak, bu etkileşimler arasında kötü niyetli saldırılar da bulunabilir.

🔴Keylogger ile Şifre Çalma: Kullanıcının klavye hareketlerini takip etme.

🔴Phishing saldırıları(kimlik avı) için sahte giriş formları oluşturulabilir.

### Stored XSS

 Saldırganın zararlı javaScript kodunu veritabanına veya başka depolama birimine kaydetmesi sonucunda kodun sayfa içerisinde otomatik olarak çalışmasıdır.

 Stored XSS ile Yapılabilecek Saldırılar

🔴 Kullanıcı Hesaplarını Ele Geçirmek

🔴 Admin Yetkilerini Ele Geçirmek

🔴 Web Sitesini Manipüle Etmek

Şu alanlara eklenebilirler:

* bir blog yazısındaki yorumlar

* bir sohbet odasındaki kullanıcı takma adları 

* bir müşteri siparişindeki iletişim bilgileri.

### DOM-based XSS

Bu XSS türünü açıklamadan önce DOOM nedir bakalım:

HTML veya XML içeriğinin bir nesne hiyerarşisidir.

DOM, sayfa üzerindeki her öğeyi (başlıklar, paragraflar, bağlantılar, resimler, formlar vb.) bir nesne (object) olarak temsil eder ve bu nesneler üzerinde işlemler yapabilmeyi  sağlar.

### DOM'un Temel Yapıları

Doküman (Document):HTML sayfası


Elementler (Elements)
HTML etiketleri, sayfanın içeriğini temsil eder. Örnekler:
(`<div>`,`<h1>`,`<p>`)

Attributes (Öznitelikler)
HTML etiketlerinin özelliklerini tanımlar. Örnekler:
(`id`,`class`,`href`)


Metin (Text)
HTML etiketleri arasında bulunan içerik. Örnek:
`<p> METİN  </p>`

![](./assets/DOM.png
 "GitHub")

DOM-based XSS Nedir?
bir web uygulamasının istemci tarafındaki (client-side) JavaScript kodu üzerinden gerçekleştirilen bir XSS türüdür. Bu saldırı türü, sunucu tarafı ile doğrudan bir ilişkisi olmadığı için, yalnızca tarayıcıda gerçekleşir. Yani, sunucu zararlı kodu almaz veya geri göndermez. Verilerin DOM'a yerleştirilmesi sırasında zararlı JavaScript çalıştırılır. Bu tür XSS saldırılarını önlemek için veri doğrulama, temizleme ve güvenli JavaScript metodları kullanılmalıdır

## SQL injection(SQLi)
Bir saldırganın bir uygulamanın veritabanına yaptığı sorgularla etkileşimde bulunmasına olanak tanıyan bir web güvenlik açığıdır. Birçok durumda, bir saldırgan bu verileri değiştirebilir veya silebilir, bu da uygulamanın içeriğinde  davranışında  değişikliklere neden olabilir.


Bir kullanıcı, bir form üzerinden veri gönderdiğinde, eğer bu veri doğru şekilde filtrelenmezse, sorgunun içine sızabilir.


```SQL
SELECT * FROM Users WHERE UserId = 105 OR 1=1;
 ``` 
1=1 her zaman true döneceği için bu tablodaki tüm bilgilere saldırgan erişebilir.
```

SELECT * FROM Users WHERE Name ="" or ""="" AND Pass ="" or ""=""
```
Ya da bu şekilde boşluk eşittir boşluk gibi.


SQL Injection Türleri:
1. In-Band SQL Injection (Açık Kanal Üzerinden)
2. Blind SQL Injection (Kör SQL Injection)

 

## **💣 A- In-band SQLi (aynı kanal üzerinden saldırı):**
Bu en yaygın SQL Injection türüdür. Saldırgan, aynı kanal üzerinden hem saldırıyı gerçekleştirir hem de sonucu alır.


📌 **Error-based SQLi**:Saldırgan, uygulamanın döndürdüğü hata mesajlarından yararlanarak veritabanı hakkında bilgi toplar.

```SQL
SELECT * FROM users WHERE id = 1' 
``` 

Eğer sistem doğrudan SQL hatasını kullanıcıya gösteriyorsa, saldırgan tablo yapısını görebilir ve sorgularını buna göre oluşturabilir.

Kısaca: Saldırgan, uygulamanın döndürdüğü hata mesajlarını kullanarak veritabanı hakkında bilgi toplar.




📌**Union-based SQLi**: UNION komutuyla farklı sorgular birleştirilir ve veriler çıkarılır.
  
```SQL
SELECT username, password FROM users WHERE id = 1 UNION SELECT username, password FROM admin_users;
``` 
Örneğin, aşağıdaki sorgu saldırganın tüm kullanıcı adlarını ve şifrelerini almasını sağlar:


## **💣Blind SQLi (Kör SQLi):**

Bu tür saldırılar doğrudan hata mesajı döndürmez.

📌  **Boolean-based Blind SQLi**: Saldırgan, doğru veya yanlış koşullara dayalı sorgular yaparak sistemin verdiği yanıtları gözlemler.
```SQL
 AND 1=1 --  /* Doğruysa sayfa normal yüklenir */
 AND 1=2 --  /* Yanlışsa sayfa farklı yanıt verir */
```
Eğer ilk sorguda sayfa normal açılıyorsa ama ikinci sorguda hata veriyorsa, bu SQL Injection’a açık olduğunu gösterir.



📌  **Time-based Blind SQLi**: Sorgu, belirtilen bir süreyi beklerse doğru kabul edilir, aksi takdirde yanlış kabul edilir.


SQL sorguları genellikle uygulama tarafından senkronize bir şekilde işlendiğinden, bir SQL sorgusunun yürütülmesini geciktirmek, HTTP yanıtını da geciktirir. Bu, HTTP yanıtını almak için geçen süreye dayanarak enjekte edilen koşulun doğruluğunu belirlemenizi sağlar.

Kısaca: Sunucu hata mesajı göstermese bile, sorgu yanıt süresi üzerinden veri sızdırılabilir.Sayfanın normalden daha geç yüklenmesi, saldırganın sorgusunun çalıştığını gösterir.
```SQL
 OR IF(1=1, SLEEP(5), 0) --  
```
Eğer sayfa 5 saniye boyunca bekledikten sonra açılıyorsa, saldırgan sorgusunun çalıştığını anlar.

## **💣Out-of-band SQLi (Farklı kanal üzerinden saldırı)**

Veritabanından çıkarılan verilerin farklı bir kanal üzerinden saldırgana gönderildiği SQL Injection türüdür.

Hata türü göstermeyen ve süreden veritabanı hakkında bilgi çıkarılmadığı zaman kullanılır.

DNS,HTTP ve FTP gibi farklı kanallar üzerinden aktarım yapılır.


Bu tür saldırıların başarılı olabilmesi için, uygulamanın ve veritabanının harici bir sunucuya veri gönderme yeteneği olması gerekir.

Eğer saldırgan veritabanı sunucusunu dışarıya veri gönderecek şekilde manipüle edebilirse, veritabanından alınan hassas bilgiler dışarıya sızdırılabilir.


### Bu saldırılardan korunma

- Hazırlanmış sorgular kullanmak,

- Güçlü erişim kontrolleri ve dış bağlantıları engellemek,

- Firewall kullanmak OOB SQLi'yi engellemek için en etkili yöntemlerdir.


## Cross-Site Request Forgery (CSRF):

 Cross-Site Request Forgery (CSRF), bir web uygulamasında kullanıcının kimlik doğrulama bilgilerini kötüye kullanarak, kullanıcı adına istenmeyen işlemler gerçekleştiren bir saldırı türüdür. CSRF saldırıları, genellikle kullanıcının oturumu açıkken ve kimlik doğrulaması yapıldıktan sonra gerçekleşir. Bu tür saldırılar, kullanıcının bilerek veya bilmeyerek zararlı bir işlem yapmasına yol açabilir.

 Örneğin, bu, kullanıcının hesabındaki e-posta adresini değiştirmek, şifresini değiştirmek veya para transferi yapmak olabilir. Eylemin niteliğine bağlı olarak, saldırgan kullanıcının hesabı üzerinde tam kontrol elde edebilir. Eğer tehlikeye atılan kullanıcı uygulama içinde ayrıcalıklı bir role sahipse, o zaman saldırgan uygulamanın tüm verileri ve işlevselliği üzerinde tam kontrol elde edebilir.

**CSRF Saldırısının Çalışma Prensibi**:

Kullanıcı bir sosyal medya platformu veya online bankacılık gibi bir siteye giriş yapmış ve oturum açmış bir kullanıcı, web tarayıcısında açık oturumla dolaşmaktadır.

Saldırgan, kurbanın ziyaret etmesi için bir bağlantı veya kötü amaçlı bir HTML formu hazırlar. Bu form, kurbanın oturumu açıkken, zararlı bir işlem yapacak şekilde hazırlanmıştır.

Kullanıcı, Kötü Niyetli Sayfayı Ziyaret Eder.Bu ziyaret sırasında, kullanıcının tarayıcısı, daha önce oturum açtığı web sitesinin çerezini otomatik olarak gönderir.

Web uygulaması işlemi onaylar. Web uygulaması, gelen isteği geçerli bir istek olarak kabul eder, çünkü kullanıcının oturumu zaten açık ve kimliği doğrulanmış durumdadır. Bu sebeple, uygulama güvenlik kontrollerini atlar ve isteği uygular.


| **CSRF Koruması**       |  **XSS Koruması**|**SQL Injection Koruması**|
|---------------------------|-------------|-----------------------|
| Token Kullanımı: Her form veya istek için sunucudan alınan benzersiz bir token eklenmeli. Sunucu, gelen istekteki tokeni doğrulamalı.|Girdi Doğrulama ve Temizleme: Kullanıcı girdileri filtrelenmeli ve HTML/JavaScript gibi zararlı kodlar temizlenmeli.|Hazırlıklı Sorgular (Prepared Statements): Kullanıcı girdileri SQL sorgularına doğrudan eklenmemeli, yerine parametre bağlama (bindParam(), bindValue()) gibi yöntemler kullanılmalı.
| **SameSite Çerez Politikası**  Çerezlerin sadece aynı site içinde çalışmasını sağlama. |Escape İşlemi: HTML çıktıları htmlspecialchars() veya e() gibi fonksiyonlarla kaçırılmalı.|ORM Kullanımı: Laravel gibi framework’lerde Eloquent gibi ORM araçları kullanarak güvenli veri çekme işlemleri yapılmalı.|
| Origin başlıklarını kontrol et ve yalnızca güvenilir kaynaklardan gelen istekleri kabul et.|CSP (Content Security Policy) kullanarak yalnızca güvenilir kaynaklardan script çalıştırılmasını sağla|WHERE gibi sorguları dinamik olarak kullanıcıdan almaktan kaçın.|



## Authentication (Kimlik Doğrulama) Nedir?

Kullanıcının iddia ettiği kişi olup olmadığının kanıtlanması. Genel olarak bir websitemizde kullanabileceğimiz 3 çeşit Authentication yöntemi mevcuttur:

* Something you know
* Something you have
* Something you are or do

Her birini açıklayarak yazımıza devam edelim.

### Authentication Yöntemleri

1. **Bilgiye Dayalı Kimlik Doğrulama (Something You Know)**

   Kullanıcının bildiği bir bilgiyle yapılan doğrulamadır.

Örnekler:

* Kullanıcı adı ve şifre

* PIN kodu

* Gizli güvenlik soruları

🔴 Zayıf Noktalar:

Şifrenin unutulması,sosyal mühendislikle şifrelerimizi ele geçirebilirler.


2. **Sahipliğe Dayalı Kimlik Doğrulama (Something You Have)**

   Kullanıcının fiziksel olarak sahip olduğu bir şey ile yapılan doğrulamadır.

Örnekler:

* SMS veya e-posta ile doğrulama kodu

* Güvenlik anahtarları 

🔴 Zayıf Noktalar:

Telefon veya güvenlik cihazı çalınabilir.

SIM kart dolandırıcılığı (SIM Swap) ile SMS kodları ele geçirilebilir.

3. **Biyometrik Kimlik Doğrulama (Something You Are)**

Kullanıcının fiziksel özellikleri ile yapılan doğrulamadır.

Örnekler:

* Parmak izi

* Yüz tanıma

* Retina veya iris taraması

* Ses tanıma



🔴
Zayıf Noktalar:

Yüksek maliyetli olabilir.

Yanlış pozitif veya yanlış negatif sonuçlar çıkabilir.

Verilerin çalınması durumunda geri alınamaz (şifre değiştirilebilir ama parmak izi değiştirilemez).


4. Davranışsal Kimlik Doğrulama (Something You Do)
Kullanıcının belirli bir eylemi nasıl yaptığına dayalı kimlik doğrulama türüdür.

Örnekler:

* Klavye yazım hızı ve ritmi

* Dokunmatik ekranda kaydırma hareketleri

* Fare hareketleri

🔴 Zayıf Noktalar:

Hassas cihazlara ihtiyaç duyabilir.

Kullanıcıların davranışları zamanla değişebilir.

Çok Faktörlü Kimlik Doğrulama (MFA - Multi-Factor Authentication)
MFA, birden fazla doğrulama yöntemi kullanarak güvenliği artırır.

2FA (İki Faktörlü Kimlik Doğrulama), en yaygın MFA yöntemidir.

Örnek:

Kullanıcı adı + Şifre (Bilgi)

SMS ile gelen kod (Sahiplik)

📌 En güvenli MFA kombinasyonu:

Şifre + OTP (Google Authenticator, Authy, Microsoft Authenticator gibi uygulamalar)

Şifre + Donanım Güvenlik Anahtarı (YubiKey gibi)

## Kimlik Doğrulama Türleri

1. Tek Aşamalı Kimlik Doğrulama (Single-Factor Authentication - SFA)
Sadece tek bir doğrulama yöntemi kullanılır.

Örnek: Kullanıcı adı ve şifre ile giriş yapmak.
🔴 Riskli! Kolayca ele geçirilebilir.

2. Çift Aşamalı Kimlik Doğrulama (Two-Factor Authentication - 2FA)
İki farklı doğrulama faktörü kullanılır.

Örnek: Şifre + SMS kodu.
✅ Daha güvenli.

3. Sürekli Kimlik Doğrulama (Continuous Authentication)
Kullanıcı oturum açtıktan sonra bile sürekli olarak kimlik doğrulaması yapılır.

Örnek: Kullanıcının yüzü veya sesi sürekli analiz edilir.
✅ Daha güvenli ama kaynak tüketimi fazla.



🔹 Authentication (Kimlik Doğrulama): "Sen kimsin?"

🔹 Authorization (Yetkilendirme): "Ne yapmana izin var?"

## Authorization (Yetkilendirme) Nedir?
Authorization (Yetkilendirme), kimliği doğrulanan bir kullanıcının belirli kaynaklara veya işlemlere erişim yetkisinin olup olmadığını belirleme sürecidir.


### Authorization Yöntemleri
1. **Rol Tabanlı Erişim Kontrolü (RBAC - Role-Based Access Control)**

* Kullanıcılar belirli roller ile gruplandırılır.

* Yetkilendirme, bu rollere göre belirlenir.

* Örnek:

      Admin → Kullanıcı yönetimi, veri düzenleme
      Editor → İçerik ekleme, düzenleme
      User → İçeriği sadece görüntüleme

  Avantajlar:

  ✔ Kolay yönetilebilir.

   ✔ Kullanıcı sayısı arttıkça yönetim kolaylığı sağlar.

🔴 Dezavantajlar:

❌ Esnek değildir; İşler karmaşıklaştıkça yetersiz kalıyor.


2. **Yetki Tabanlı Erişim Kontrolü (PBAC - Permission-Based Access Control)**

Bu, kaynaklara erişimi politikalara göre yöneten bir güvenlik modelidir.

Rol Tabanlı Erişim Kontrolü'nün (RBAC) roller üzerine odaklanmasının aksine, PBAC, aşağıdakiler gibi çeşitli nitelikleri dikkate alabilen politikalar kullanır:

* Kullanıcı nitelikleri (ör. iş unvanı, konum)
* Kaynak nitelikleri (ör. dosya türü, hassasiyet)
* Çevresel nitelikler (ör. günün saati, ağ konumu)

PBAC, erişim kontrolünde daha fazla esneklik ve ayrıntı düzeyi sunar.

![alt text](./assets/Autherization.PNG
 "GitHub")

Örneğin:

Politika 1: Bir kullanıcı yalnızca HR departmanı çalışanıysa personel bilgilerine erişebilir.

Politika 2: Sadece yöneticiler belirli finansal verilere erişebilir.

Politika 3: Mesai saatleri dışında herhangi bir kullanıcı sistem erişimi sağlayamaz.


**Öznitelik Tabanlı Erişim Kontrolü (Attribute-Based Access Control (ABAC))**

 Bu modelde, kullanıcılara, kaynaklara ve hatta erişim talebine (örneğin zaman, yer, işlem türü) dayalı olarak erişim izni verilir. ABAC, çok daha esnek ve dinamik bir yetkilendirme sağlar çünkü erişim kararları, yalnızca kullanıcının rolü veya kimliği değil, birçok faktöre dayanarak alınır.

  Bu öznitelikler, kullanıcının kimliği, rolü, departmanı, çalıştığı saat, kaynağın türü ve güvenlik seviyesi, hatta çevresel faktörler (örneğin kullanıcı IP adresi veya lokasyonu) gibi bilgiler olabilir.

  Bileşenler:
* Kullanıcı Öznitelikleri: Kullanıcıyla ilgili bilgiler (örneğin, rol, departman, güvenlik seviyesi, yaş, konum).

* Kaynak Öznitelikleri: Erişilmeye çalışılan kaynakla ilgili bilgiler (örneğin, dosyanın türü, güvenlik seviyesi, sahibi).

* Erişim Talebi Öznitelikleri: Erişim talebinin bağlamı ile ilgili bilgiler (örneğin, saat, tarih, IP adresi, cihaz türü).

* Politikalar: Erişim iznini tanımlayan kurallar. Bu kurallar genellikle kullanıcının ve kaynağın özniteliklerine dayalıdır.

3. **Zorunlu Erişim Kontrolü (MAC - Mandatory Access Control)**


MAC (Mandatory Access Control), sistemdeki erişim kurallarının zorunlu olarak uygulandığı bir modeldir. Kullanıcılar ve gruplar, yalnızca belirli kurallara ve politikalarla erişim izni alır. Bu genellikle yüksek güvenlikli sistemlerde, örneğin askeri veya hükümet sistemlerinde kullanılır.Merkezi bir otoritenin yönlendirmesi altında sistemin kendisi verir.

Gizlilik Seviyeleri: "Halka Açık", "Sınırlı", "Özel", "Çok Gizli" gibi seviyeler vardır.

----
Örneğin, kimlik doğrulama, bugra123 kullanıcı adıyla bir web sitesine erişmeye çalışan birinin gerçekten hesabı oluşturan kişi olup olmadığını belirler.

bugra123 kimlik doğrulandıktan sonra, izinleri neyi yapma yetkisine sahip olduğunu belirler. Örneğin, diğer kullanıcılar hakkında kişisel bilgilere erişim iznine sahip olabilir veya başka bir kullanıcının hesabını silme gibi işlemleri gerçekleştirebilir.

# Oauth

Muhtemelen sosyal medya hesabınızı kullanarak giriş yapmanıza izin veren sitelerle karşılaşmışsınızdır. Bu özelliğin,  OAuth 2.0  kullanılarak oluşturulmuş olma ihtimali yüksektir.

* web sitelerinin ve web uygulamalarının başka bir uygulamadaki bir kullanıcının hesabına sınırlı erişim talep etmesini sağlayan yaygın olarak kullanılan bir yetkilendirme çerçevesidir. 

*  kullanıcı adı ve şifre paylaşmadan bir uygulamanın başka bir uygulamaya güvenli bir şekilde erişim izni vermesini sağlayan yetkilendirme protokolüdür.

* Örneğin, "Google ile Giriş Yap" veya "Discord ile Bağlan" gibi işlemler OAuth 2.0 ile gerçekleştirilir.

* Kullanıcı şifresini doğrudan paylaşmaz, bunun yerine Access Token kullanılır.

OpenID
OpenID, kullanıcıların kimlik doğrulaması yapmak için kullanılan bir açık standarttır.

OAuth 2.0 ile birlikte çalışır.

OpenID, genellikle tek oturum açma ve kimlik doğrulama işlemleri için kullanılır.



Detaylı bilgi için [Ouath ve OpenID makalem](https://github.com/xBugor/OauthAndOpenID)
## KAYNAKÇA


## Queue&Job

Queue (Kuyruk)
 kuyruk, işlemlerin sıralı bir şekilde yapılmasını sağlar. Kuyruğa bir iş (job) eklendiğinde, o iş bir sonraki uygun zaman geldiğinde işlenir. Bu, zaman alıcı işlemlerin kullanıcı etkileşimi sırasında engellenmeden yapılmasını sağlar. Kuyruklar, özellikle e-posta gönderme, veri işleme, bildirim gönderme gibi işlemleri arka planda yaparken kullanılabilir.

Kuyruk Kullanımının Avantajları:
Zaman alıcı işlemleri arka planda yapma: Kullanıcıların hızlı yanıt almasını sağlar.

İş yükünü dağıtma: Kuyruklar, işlemleri farklı işçiler (workers) arasında dağıtarak verimli hale gelir.

İşlerin sırasıyla yapılması: Kuyrukta işler sırasıyla işlenir, yani bir iş tamamlanmadan diğerine geçilmez.

Job (İş)
Bir Job, bir kuyruğa eklenen bir işlem veya görev anlamına gelir. Kuyruğa eklenen her iş bir Job'dur. Örneğin, bir e-posta göndermek, bir dosya yüklemek veya bir veri tabanı işlemi yapmak birer Job olabilir. Job'lar, kuyrukta bekleyen işlemleri temsil eder ve işçi (worker) tarafından işlenir.

Job Özellikleri:
İşin tanımlanması: Bir job, yapılacak işlemi tanımlar. Örneğin, "E-posta gönder" bir job olabilir.

Bir kuyruğa eklenmesi: Job'lar, kuyruklar aracılığıyla zamanlanır ve işlenir.

Arka planda çalışması: Kuyrukta işleme alınan job'lar, arka planda çalışır ve kullanıcının etkileşimine engel olmaz.






[Medium](https://medium.com/@YunusEmreAlpu/cross-site-scripting-xss-nedir-77ffbd12e718)

[Bulutistan](https://bulutistan.com/blog/xss-cross-site-scripting-nedir/)

[Port Swinger](https://portswigger.net/web-security/cross-site-scripting)

[Wikipedia](wwww.wikepedia.com)

[Bergnet](https://berqnet.com/blog/xss-zafiyeti-cross-site-scripting)

[NetsParker](https://medium.com/@hhuseyinuyar17/xss-zafiyeti-hakkında-98b5849d4700)

[W3School](https://www.w3schools.com/js/js_htmldom.asp)

[Port Swinger SQLi](https://portswigger.net/web-security/sql-injection/blind)

[imperva SQLi](https://www.imperva.com/learn/application-security/sql-injection-sqli/)

[w3schools SQLi](https://www.w3schools.com/sql/sql_injection.asp)

[Port Swinger CSRF](https://portswigger.net/web-security/csrf)

[Port Swinger authentication ](https://portswigger.net/web-security/authentication)

[frontegg.com](https://frontegg.com/guides/authorization-a-complete-guide)

[nextlabs pbca](https://www.nextlabs.com/products/cloudaz-policy-platform/what-is-policy-based-access-control-pbac/)
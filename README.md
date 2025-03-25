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

# DOM'un Temel Yapısı

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
